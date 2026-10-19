package web

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// authOptions are the authorize parameters common to login and step-up.
func (s *Server) authOptions(p *Pending, stepUp bool) []oauth2.AuthCodeOption {
	opts := []oauth2.AuthCodeOption{oidc.Nonce(p.Nonce), oauth2.S256ChallengeOption(p.CodeVerifier)}
	if stepUp {
		// Force a new interactive sign-in for this approval.
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	if ctxID, ok := strings.CutPrefix(s.verifier.Config().MFAClaim, "acrs:"); ok {
		// Ask for the Conditional Access authentication context that
		// requires MFA; Entra then puts it in the acrs claim.
		claims, _ := json.Marshal(map[string]any{"id_token": map[string]any{
			"acrs": map[string]any{"essential": true, "value": ctxID},
		}})
		opts = append(opts, oauth2.SetAuthURLParam("claims", string(claims)))
	}
	return opts
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	sess := s.newSession()
	p := &Pending{Purpose: "login", State: ids.NewSecret(24), Nonce: ids.NewSecret(24),
		CodeVerifier: oauth2.GenerateVerifier(), StartedAt: s.now()}
	sess.data.Pending = p
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, s.oauth.AuthCodeURL(p.State, s.authOptions(p, false)...), http.StatusSeeOther)
}

// startStepUp sends the operator to the identity provider to approve req.
func (s *Server) startStepUp(w http.ResponseWriter, r *http.Request, sess *session, req *openrmmv1.JobRequest, ret string) {
	raw, err := proto.Marshal(req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := &Pending{Purpose: "job", State: ids.NewSecret(24), Nonce: jobreq.AuthNonce(req),
		CodeVerifier: oauth2.GenerateVerifier(), StartedAt: s.now(), JobRequest: raw, Return: ret}
	sess.data.Pending = p
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	opts := append(s.authOptions(p, true), oauth2.SetAuthURLParam("login_hint", sess.data.Operator.Username))
	http.Redirect(w, r, s.oauth.AuthCodeURL(p.State, opts...), http.StatusSeeOther)
}

func (s *Server) exchange(ctx context.Context, code, verifier string) (string, error) {
	if s.client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, s.client)
	}
	tok, err := s.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", err
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", errors.New("no id_token in the token response")
	}
	return raw, nil
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	sess := s.loadSession(r)
	lang := langOf(r, sess)
	if sess == nil || sess.data.Pending == nil {
		http.Error(w, tr(lang, "accesso non avviato o scaduto: riprova"), http.StatusBadRequest)
		return
	}
	p := sess.data.Pending
	sess.data.Pending = nil // single use, whatever happens next
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.log.Warn("identity provider error", "error", e, "description", q.Get("error_description"))
		http.Error(w, trf(lang, "accesso non riuscito: %s", e), http.StatusUnauthorized)
		return
	}
	if q.Get("state") == "" || q.Get("state") != p.State || s.now().Sub(p.StartedAt) > pendingMaxAge {
		http.Error(w, tr(lang, "accesso non valido o scaduto: riprova"), http.StatusBadRequest)
		return
	}
	raw, err := s.exchange(r.Context(), q.Get("code"), p.CodeVerifier)
	if err != nil {
		s.log.Warn("token exchange failed", "err", err)
		http.Error(w, tr(lang, "accesso non riuscito"), http.StatusUnauthorized)
		return
	}
	claims, err := s.verifier.Verify(r.Context(), raw)
	if err != nil {
		s.log.Warn("operator token rejected", "err", err)
		msg := tr(lang, "accesso negato")
		switch {
		case errors.Is(err, authn.ErrNoMFA):
			msg = tr(lang, "accesso negato: è richiesta l'autenticazione a più fattori")
		case errors.Is(err, authn.ErrNoRole):
			msg = tr(lang, "accesso negato: nessun ruolo open-rmm assegnato")
		case errors.Is(err, authn.ErrNoTenant):
			msg = tr(lang, "accesso negato: directory non autorizzata")
		}
		http.Error(w, msg, http.StatusForbidden)
		return
	}
	switch p.Purpose {
	case "login":
		if claims.Nonce != p.Nonce {
			http.Error(w, tr(lang, "accesso non valido"), http.StatusBadRequest)
			return
		}
		s.completeLogin(w, r, sess, claims)
	case "job":
		s.completeJob(w, r, sess, p, claims, raw)
	case "policy":
		s.completePolicy(w, r, sess, p, claims, raw)
	default:
		http.Error(w, tr(lang, "accesso non valido"), http.StatusBadRequest)
	}
}

func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, old *session, c *authn.Claims) {
	tenants := s.verifier.Tenants(c)
	s.destroy(r.Context(), w, old)
	sess := s.newSession()
	sess.data.Operator = &Operator{ObjectID: c.ObjectID, TenantID: c.TenantID, Name: c.Name, Username: c.Username,
		Roles: c.Roles, Tenants: tenants}
	if len(tenants) > 0 {
		sess.data.Tenant = tenants[0]
	}
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	for _, t := range tenants {
		s.audit(r.Context(), t, sess.data.Operator, "operator.login", c.ObjectID, map[string]any{"roles": c.Roles})
	}
	s.log.Info("operator login", "operator", c.Operator(), "roles", c.Roles)
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

func (s *Server) completeJob(w http.ResponseWriter, r *http.Request, sess *session, p *Pending, c *authn.Claims, rawToken string) {
	op, lang := sess.data.Operator, langOf(r, sess)
	if op == nil {
		http.Error(w, tr(lang, "sessione scaduta"), http.StatusUnauthorized)
		return
	}
	// The approval must come from the logged-in operator.
	if c.ObjectID != op.ObjectID || c.TenantID != op.TenantID {
		s.log.Warn("step-up by another identity", "session", op.ObjectID, "token", c.ObjectID)
		http.Error(w, tr(lang, "l'approvazione deve essere fatta dallo stesso operatore"), http.StatusForbidden)
		return
	}
	req := &openrmmv1.JobRequest{}
	if err := proto.Unmarshal(p.JobRequest, req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !jobreq.CheckAuthNonce(c.Nonce, req) {
		http.Error(w, tr(lang, "approvazione non valida per questa richiesta"), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := s.signer.SignJob(ctx, &openrmmv1.SignJobRequest{Request: req, IdToken: rawToken})
	if err != nil {
		s.log.Warn("signer refused job", "err", err, "operator", op.Username)
		s.audit(r.Context(), req.GetTenantId(), op, "job.refused", req.GetAgentId(), map[string]any{
			"module": req.GetModule(), "action": req.GetAction(), "reason": err.Error()})
		s.flashTo(w, r, sess, trf(lang, "Il servizio di firma ha rifiutato il comando: %v", err), p.Return)
		return
	}
	var pkgs []string
	for _, p := range req.GetPackages() {
		pkgs = append(pkgs, hex.EncodeToString(p.GetSha256()))
	}
	var created []string
	for _, sj := range resp.GetJobs() {
		j := store.Job{
			TenantID: req.GetTenantId(), ID: sj.GetJobId(), AgentID: sj.GetAgentId(),
			Module: req.GetModule(), ModuleVersion: req.GetModuleVersion(), Action: req.GetAction(),
			Params: req.GetParamsJson(), Envelope: sj.GetEnvelope(), CreatedBy: "operator:" + op.Username,
			ExpiresAt: time.Unix(resp.GetExpiresUnix(), 0), Packages: pkgs,
		}
		if err := s.store.CreateJob(r.Context(), j); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), req.GetTenantId(), op, "job.created", j.ID, map[string]any{
			"agent": j.AgentID, "module": j.Module, "version": j.ModuleVersion, "action": j.Action,
			"params": json.RawMessage(j.Params), "packages": pkgs, "approved_by": resp.GetOperator(),
		})
		created = append(created, j.ID)
	}
	switch len(created) {
	case 0:
		s.fail(w, r, errors.New("signer returned no jobs"))
	case 1:
		http.Redirect(w, r, "/jobs/"+created[0], http.StatusSeeOther)
	default:
		s.flashTo(w, r, sess, trf(lang, "%d comandi approvati e in coda.", len(created)), "/jobs")
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.destroy(r.Context(), w, sessionFrom(r.Context()))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) audit(ctx context.Context, tenantID string, op *Operator, action, target string, details map[string]any) {
	if _, err := s.store.AppendAudit(ctx, audit.Event{TenantID: tenantID, Actor: "operator:" + op.Username + " (" + op.ObjectID + ")",
		Action: action, Target: target, OccurredAt: s.now(), Details: details}); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
}
