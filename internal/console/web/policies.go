package web

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/policy"
)

// formRule is the editable form of a rule: modules are referenced by id and
// version, the console fills in the manifest hash.
type formRule struct {
	ID      string            `json:"id"`
	Module  string            `json:"module"`
	Version string            `json:"version"`
	Action  string            `json:"action"`
	Every   string            `json:"every"` // Go duration, e.g. "15m", "24h"
	Params  json.RawMessage   `json:"params,omitempty"`
	When    *policy.Condition `json:"when,omitempty"`
	Window  *policy.Window    `json:"window,omitempty"`
}

type policyView struct {
	store.PolicyVersion
	Rules int
}

type policiesData struct{ Policies []policyView }

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	cur, err := s.store.CurrentPolicies(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	var d policiesData
	for _, p := range cur {
		v := policyView{PolicyVersion: p}
		if pol, err := policy.Parse(p.Document); err == nil {
			v.Rules = len(pol.Rules)
		}
		d.Policies = append(d.Policies, v)
	}
	s.render(w, r, "policies", "Policy", d)
}

type policyFormData struct {
	ID        string
	Name      string
	AppliesTo string
	Version   int64
	Rules     string
	Example   string
}

const exampleRules = `[
  {
    "id": "sysinfo",
    "module": "sysinfo",
    "version": "1.0.0",
    "action": "info",
    "every": "24h"
  },
  {
    "id": "trend-swp",
    "module": "trendmicro-endpoint",
    "version": "1.0.0",
    "action": "status",
    "every": "15m",
    "when": { "service_exists": "ds_agent" }
  }
]`

func (s *Server) handlePolicyForm(w http.ResponseWriter, r *http.Request) {
	t, _ := tenantOf(r)
	d := policyFormData{AppliesTo: policy.AppliesAll, Rules: "[]", Example: exampleRules}
	if r.URL.Query().Get("template") == "baseline" && r.PathValue("id") == "" {
		rules, err := s.baselineRules(r)
		if err != nil {
			s.fail(w, err)
			return
		}
		d.Name, d.Rules = "Base", rules
	}
	if id := r.PathValue("id"); id != "" {
		cur, err := s.store.GetPolicy(r.Context(), t, id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		p, err := policy.Parse(cur.Document)
		if err != nil {
			s.fail(w, err)
			return
		}
		rules := make([]formRule, 0, len(p.Rules))
		for _, ru := range p.Rules {
			rules = append(rules, formRule{ID: ru.ID, Module: ru.Module, Version: ru.ModuleVersion, Action: ru.Action,
				Every: ru.Every().String(), Params: ru.Params, When: ru.When, Window: ru.Window})
		}
		b, _ := json.MarshalIndent(rules, "", "  ")
		d = policyFormData{ID: p.ID, Name: p.Name, AppliesTo: p.AppliesTo, Version: p.Version, Rules: string(b), Example: exampleRules}
	}
	title := "Nuova policy"
	if d.ID != "" {
		title = "Modifica policy"
	}
	s.render(w, r, "policy_form", title, d)
}

// buildPolicy turns the form into a validated, canonical policy document.
func (s *Server) buildPolicy(ctx context.Context, tenant string, r *http.Request) (*policy.Policy, []byte, error) {
	id := r.PostFormValue("id")
	version := int64(1)
	if id != "" {
		if !ids.IsUUID(id) {
			return nil, nil, errors.New("policy non valida")
		}
		cur, err := s.store.GetPolicy(ctx, tenant, id)
		if err != nil {
			return nil, nil, errors.New("policy non trovata")
		}
		version = cur.Version + 1
	} else {
		id = ids.NewUUID()
	}
	var rules []formRule
	dec := json.NewDecoder(strings.NewReader(r.PostFormValue("rules")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rules); err != nil {
		return nil, nil, fmt.Errorf("regole: JSON non valido: %v", err)
	}
	p := &policy.Policy{ID: id, TenantID: tenant, Name: strings.TrimSpace(r.PostFormValue("name")), Version: version,
		AppliesTo: r.PostFormValue("applies_to")}
	for _, fr := range rules {
		every, err := time.ParseDuration(fr.Every)
		if err != nil {
			return nil, nil, fmt.Errorf("regola %q: intervallo non valido (es. 15m, 24h)", fr.ID)
		}
		mod, err := s.store.GetModule(ctx, fr.Module, fr.Version)
		if err != nil {
			return nil, nil, fmt.Errorf("regola %q: modulo %s %s non pubblicato", fr.ID, fr.Module, fr.Version)
		}
		man, err := modules.ParseManifest(mod.Manifest)
		if err != nil {
			return nil, nil, err
		}
		if _, ok := man.Actions[fr.Action]; !ok {
			return nil, nil, fmt.Errorf("regola %q: il modulo %s non ha l'azione %q", fr.ID, fr.Module, fr.Action)
		}
		if man.HasCapability(modules.CapAdHocScript) {
			return nil, nil, fmt.Errorf("regola %q: i moduli che eseguono script non possono stare in una policy", fr.ID)
		}
		p.Rules = append(p.Rules, policy.Rule{ID: fr.ID, Module: fr.Module, ModuleVersion: fr.Version,
			ModuleSHA256: hex.EncodeToString(mod.ManifestSHA256), Action: fr.Action, Params: fr.Params,
			EverySeconds: int64(every / time.Second), When: fr.When, Window: fr.Window})
	}
	if err := p.Validate(); err != nil {
		return nil, nil, err
	}
	raw, err := p.Canonical()
	return p, raw, err
}

// handleSavePolicy validates the form and starts the step-up approval of the
// exact document; it is stored once the signer has signed it.
func (s *Server) handleSavePolicy(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	_, raw, err := s.buildPolicy(r.Context(), t, r)
	if err != nil {
		d := policyFormData{ID: r.PostFormValue("id"), Name: r.PostFormValue("name"), AppliesTo: r.PostFormValue("applies_to"),
			Rules: r.PostFormValue("rules"), Example: exampleRules}
		sess := sessionFrom(r.Context())
		sess.data.Flash = "Policy non valida: " + err.Error()
		s.render(w, r, "policy_form", "Policy", d)
		return
	}
	sess := sessionFrom(r.Context())
	p := &Pending{Purpose: "policy", State: ids.NewSecret(24), Nonce: policy.AuthNonce(raw),
		CodeVerifier: oauth2.GenerateVerifier(), StartedAt: s.now(), PolicyDoc: raw, Return: "/policies"}
	sess.data.Pending = p
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, err)
		return
	}
	opts := append(s.authOptions(p, true), oauth2.SetAuthURLParam("login_hint", sess.data.Operator.Username))
	http.Redirect(w, r, s.oauth.AuthCodeURL(p.State, opts...), http.StatusSeeOther)
}

func (s *Server) completePolicy(w http.ResponseWriter, r *http.Request, sess *session, p *Pending, c *authn.Claims, rawToken string) {
	op := sess.data.Operator
	if op == nil {
		http.Error(w, "sessione scaduta", http.StatusUnauthorized)
		return
	}
	if c.ObjectID != op.ObjectID || c.TenantID != op.TenantID {
		http.Error(w, "l'approvazione deve essere fatta dallo stesso operatore", http.StatusForbidden)
		return
	}
	pol, err := policy.Parse(p.PolicyDoc)
	if err != nil || c.Nonce != policy.AuthNonce(p.PolicyDoc) {
		http.Error(w, "approvazione non valida per questa policy", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := s.signer.SignPolicy(ctx, &openrmmv1.SignPolicyRequest{TenantId: pol.TenantID, PolicyJson: p.PolicyDoc, IdToken: rawToken})
	if err != nil {
		s.audit(r.Context(), pol.TenantID, op, "policy.refused", pol.ID, map[string]any{"name": pol.Name, "reason": err.Error()})
		s.flashTo(w, r, sess, "Il servizio di firma ha rifiutato la policy: "+err.Error(), p.Return)
		return
	}
	if err := s.store.AddPolicyVersion(r.Context(), store.PolicyVersion{TenantID: pol.TenantID, ID: pol.ID, Version: pol.Version,
		Name: pol.Name, AppliesTo: pol.AppliesTo, Document: p.PolicyDoc, Envelope: resp.GetEnvelope(),
		CreatedBy: "operator:" + op.Username}); err != nil {
		if errors.Is(err, store.ErrPolicyVersion) {
			s.flashTo(w, r, sess, "La policy è stata modificata da qualcun altro nel frattempo: riprova.", p.Return)
			return
		}
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), pol.TenantID, op, "policy.saved", pol.ID, map[string]any{
		"name": pol.Name, "version": pol.Version, "applies_to": pol.AppliesTo, "document": json.RawMessage(p.PolicyDoc),
		"approved_by": resp.GetOperator()})
	s.flashTo(w, r, sess, fmt.Sprintf("Policy %q (versione %d) salvata: gli agenti la ricevono subito.", pol.Name, pol.Version), p.Return)
}

// handleDeletePolicy removes a policy. Removing only stops monitoring, it
// cannot run anything, so it needs the Admin role but no step-up; it is
// audited.
func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	cur, err := s.store.GetPolicy(r.Context(), t, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	if err := s.store.AddPolicyVersion(r.Context(), store.PolicyVersion{TenantID: t, ID: id, Version: cur.Version + 1,
		Name: cur.Name, AppliesTo: cur.AppliesTo, Deleted: true, CreatedBy: "operator:" + op.Username}); err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), t, op, "policy.deleted", id, map[string]any{"name": cur.Name, "version": cur.Version})
	s.flash(w, r, fmt.Sprintf("Policy %q eliminata.", cur.Name), "/policies")
}
