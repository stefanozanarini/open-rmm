package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/stefanozanarini/open-rmm/internal/accesslog"
	"github.com/stefanozanarini/open-rmm/internal/adinv"
	"github.com/stefanozanarini/open-rmm/internal/codesign"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/wingetcat"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/policy"
)

// Setup item statuses.
const (
	setupDone     = "ok"
	setupWarn     = "warning"
	setupTodo     = "failing"
	setupOptional = "optional"
)

type setupItem struct {
	Title, Status, Detail string
	Link, LinkLabel       string
}

type setupData struct {
	Items     []setupItem
	Done, All int
	Missing   []string // recommended modules not published
	CodeSign  *codesign.Chain
	CodeInfo  codesign.Info
	Expiring  bool
	HasRoot   bool
}

// recommended are the modules of a typical Windows installation, with the
// baseline policy rule of each (Every empty: no rule).
var recommended = []struct {
	Module, Action, Every string
	When                  *policy.Condition
}{
	{inventory.ModuleID, inventory.Action, "24h", nil},
	{"winupdate", "scan", "24h", nil},
	{"winget", "scan", "24h", nil},
	{"firmware", "scan", "24h", nil},
	{"protection-status", "status", "1h", nil},
	{accesslog.ModuleID, accesslog.Action, "5m", nil},
	{"trendmicro", "status", "15m", &policy.Condition{Any: []policy.Condition{
		{ServiceExists: "ntrtscan"}, {ServiceExists: "ds_agent"}, {ServiceExists: "EndpointBasecamp"}}}},
	{adinv.ModuleID, adinv.Action, "24h", &policy.Condition{ServiceExists: "NTDS"}},
	{"reboot", "", "", nil},
	{"software", "", "", nil},
	{"script", "", "", nil},
}

// latestModules maps module ids to their newest published version.
func (s *Server) latestModules(r *http.Request) (map[string]string, error) {
	mods, err := s.store.ListModules(r.Context())
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, m := range mods {
		if cur, ok := out[m.ID]; !ok || wingetcat.CompareVersions(m.Version, cur) > 0 {
			out[m.ID] = m.Version
		}
	}
	return out, nil
}

// baselineRules is the rule list of the baseline policy, with the modules
// published on this console.
func (s *Server) baselineRules(r *http.Request) (string, error) {
	latest, err := s.latestModules(r)
	if err != nil {
		return "", err
	}
	rules := []formRule{}
	for _, m := range recommended {
		v, ok := latest[m.Module]
		if !ok || m.Every == "" {
			continue
		}
		rules = append(rules, formRule{ID: m.Module, Module: m.Module, Version: v, Action: m.Action, Every: m.Every, When: m.When})
	}
	b, err := json.MarshalIndent(rules, "", "  ")
	return string(b), err
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	ctx := r.Context()
	now := s.now()
	var d setupData
	add := func(it setupItem) { d.Items = append(d.Items, it) }

	add(setupItem{Title: s.T(r, "Accesso con Entra ID e MFA"), Status: setupDone,
		Detail: s.T(r, "Gli operatori accedono con Entra ID; ogni comando e ogni policy richiede una nuova autenticazione MFA.")})

	sites, err := s.store.ListSites(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	it := setupItem{Title: s.T(r, "Sedi"), Link: "/sites", LinkLabel: s.T(r, "Sedi")}
	if len(sites) == 0 {
		it.Status, it.Detail = setupTodo, s.T(r, "Definisci le sedi con le loro subnet: gli agenti vengono raggruppati automaticamente nell'albero.")
	} else {
		it.Status, it.Detail = setupDone, s.Tf(r, "%d sedi definite.", len(sites))
	}
	add(it)

	set, err := s.store.GetSettings(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	it = setupItem{Title: s.T(r, "Reti da cui è consentito l'RDP"), Link: "/settings", LinkLabel: s.T(r, "Impostazioni")}
	if len(set.RDPAllowedSubnets) == 0 {
		it.Status, it.Detail = setupWarn, s.T(r, "Si usano le reti private predefinite. Indica le subnet delle LAN per ricevere un avviso critico sugli RDP da altre reti (VPN comprese).")
	} else {
		it.Status, it.Detail = setupDone, s.Tf(r, "%d subnet: %s.", len(set.RDPAllowedSubnets), strings.Join(set.RDPAllowedSubnets, ", "))
	}
	add(it)

	latest, err := s.latestModules(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, m := range recommended {
		if _, ok := latest[m.Module]; !ok && m.Module != adinv.ModuleID {
			d.Missing = append(d.Missing, m.Module)
		}
	}
	it = setupItem{Title: s.T(r, "Moduli"), Link: "/modules", LinkLabel: s.T(r, "Moduli")}
	if len(d.Missing) == 0 {
		it.Status, it.Detail = setupDone, s.Tf(r, "%d moduli pubblicati.", len(latest))
	} else {
		it.Status, it.Detail = setupTodo, s.Tf(r, "Da pubblicare (openrmm-admin module sign e module publish): %s.", strings.Join(d.Missing, ", "))
	}
	add(it)

	pols, err := s.store.CurrentPolicies(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	periodic := 0
	for _, m := range recommended {
		if _, ok := latest[m.Module]; ok && m.Every != "" {
			periodic++
		}
	}
	it = setupItem{Title: s.T(r, "Policy di base"), Link: "/policies/new?template=baseline", LinkLabel: s.T(r, "Crea la policy di base")}
	if len(pols) == 0 && periodic == 0 {
		it.Status, it.Detail, it.Link, it.LinkLabel = setupTodo, s.T(r, "Pubblica prima i moduli: la policy di base li esegue periodicamente."), "/modules", s.T(r, "Moduli")
	} else if len(pols) == 0 {
		it.Status, it.Detail = setupTodo, s.T(r, "Inventario, aggiornamenti, stato della protezione, accessi, Trend Micro dove installato e Active Directory sui domain controller. La policy è precompilata con i moduli pubblicati e va approvata con MFA.")
	} else {
		it.Status, it.Detail, it.Link, it.LinkLabel = setupDone, s.Tf(r, "%d policy attive.", len(pols)), "/policies", s.T(r, "Policy")
	}
	add(it)

	tokens, err := s.store.ListEnrollmentTokens(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	agents, err := s.store.ListAgents(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	usable := 0
	for _, tk := range tokens {
		if tk.RevokedAt == nil && now.Before(tk.ExpiresAt) && (tk.MaxUses == 0 || tk.Uses < tk.MaxUses) {
			usable++
		}
	}
	active, pending := 0, 0
	for _, a := range agents {
		switch a.Status {
		case store.AgentActive:
			active++
		case store.AgentPending:
			pending++
		}
	}
	it = setupItem{Title: s.T(r, "Distribuzione degli agenti"), Link: "/tokens", LinkLabel: s.T(r, "Token")}
	switch {
	case active > 0:
		it.Status, it.Detail = setupDone, s.Tf(r, "%d agenti attivi, %d in attesa di approvazione, %d token validi.", active, pending, usable)
	case usable > 0:
		it.Status, it.Detail = setupWarn, s.T(r, "Token pronto: distribuisci l'MSI con la GPO (docs/AGENT-INSTALL.md) e approva i primi agenti.")
	default:
		it.Status, it.Detail = setupTodo, s.T(r, "Crea un token di registrazione da inserire nella GPO o nelle proprietà dell'MSI.")
	}
	add(it)

	it = setupItem{Title: s.T(r, "Firma del codice (Authenticode)"), Link: "#codesign", LinkLabel: s.T(r, "Certificato")}
	if set.CodeSigningCert != "" {
		ch, err := codesign.ParseChain([]byte(set.CodeSigningCert), now)
		if err != nil {
			it.Status, it.Detail = setupTodo, s.Tf(r, "Il certificato registrato non è più valido: %v", err)
		} else {
			d.CodeSign, d.CodeInfo, d.Expiring, d.HasRoot = &ch, ch.LeafInfo(), ch.Expiring(now), ch.Root() != nil
			it.Status, it.Detail = setupDone, s.Tf(r, "Certificato %s valido fino al %s.", d.CodeInfo.Subject, d.CodeInfo.NotAfter.Format(dateFormat(s.lang(r))))
			if d.Expiring {
				it.Status, it.Detail = setupWarn, s.Tf(r, "Il certificato scade il %s: rinnovalo e ricostruisci l'MSI.", d.CodeInfo.NotAfter.Format(dateFormat(s.lang(r))))
			}
		}
	} else {
		it.Status, it.Detail = setupTodo, s.T(r, "Firma eseguibili e MSI, altrimenti SmartScreen e gli antivirus possono bloccarli.")
	}
	add(it)

	doms, err := s.store.ListADDomains(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	it = setupItem{Title: s.T(r, "Active Directory (facoltativo)"), Link: "/ad", LinkLabel: "Active Directory"}
	if len(doms) == 0 {
		it.Status, it.Detail = setupOptional, s.T(r, "Confronta i computer del dominio con gli agenti (PC senza agente, oggetti obsoleti) e raggruppa gli agenti per OU. Nessuna credenziale di AD sulla console.")
	} else {
		var names []string
		for _, dm := range doms {
			names = append(names, dm.Domain)
		}
		sort.Strings(names)
		it.Status, it.Detail = setupDone, s.Tf(r, "Domini: %s.", strings.Join(names, ", "))
	}
	add(it)

	for _, x := range d.Items {
		if x.Status == setupOptional {
			continue
		}
		d.All++
		if x.Status == setupDone {
			d.Done++
		}
	}
	s.render(w, r, "setup", s.T(r, "Configurazione"), d)
}

// handleSaveCodeSigning stores the public code-signing certificate (never a
// key) or removes it.
func (s *Server) handleSaveCodeSigning(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	cur, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	next := cur
	detail := map[string]any{}
	if r.PostFormValue("remove") != "" {
		next.CodeSigningCert = ""
		detail["removed"] = true
	} else {
		raw := strings.TrimSpace(r.PostFormValue("certificate"))
		if strings.Contains(raw, "PRIVATE KEY") {
			s.flash(w, r, s.T(r, "Hai incollato una chiave privata: non è stata salvata. Incolla solo il certificato e conserva la chiave sulla macchina di build."), "/setup#codesign")
			return
		}
		ch, err := codesign.ParseChain([]byte(raw), s.now())
		if err != nil {
			s.flash(w, r, s.Tf(r, "Certificato non valido: %v", err), "/setup#codesign")
			return
		}
		next.CodeSigningCert = raw + "\n"
		i := ch.LeafInfo()
		detail["subject"], detail["thumbprint"], detail["not_after"] = i.Subject, i.Thumbprint, i.NotAfter
	}
	if err := s.store.PutSettings(r.Context(), t, next, "operator:"+op.Username); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "settings.code_signing", t, detail)
	s.flash(w, r, s.T(r, "Certificato di firma aggiornato."), "/setup#codesign")
}

// handleCodeSigningCert serves the public certificates for Group Policy:
// codesign.cer (Trusted Publishers) and codesign-ca.cer (Trusted Root).
func (s *Server) handleCodeSigningCert(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	set, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ch, err := codesign.ParseChain([]byte(set.CodeSigningCert), s.now())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	name := r.PathValue("file")
	var der []byte
	switch name {
	case "codesign.cer":
		der = ch.Leaf.Raw
	case "codesign-ca.cer":
		if root := ch.Root(); root != nil {
			der = root.Raw
		}
	}
	if der == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if _, err := w.Write(der); err != nil {
		s.log.Debug("send certificate", "err", err)
	}
}
