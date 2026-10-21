package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/federation"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// fedStepUp is a step-up started by a linked console for one of its
// pending approvals: the central console runs the sign-in and hands the
// id_token over.
type fedStepUp struct {
	Link         string    `json:"link"`
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	StartedAt    time.Time `json:"started_at"`
}

// centralPaths are served by the central console itself even while a
// linked console is open; everything else goes over the link.
func centralPath(p string) bool {
	switch p {
	case "/healthz", "/login", "/auth/callback", "/logout", "/tenant", "/lang", "/theme":
		return true
	}
	return strings.HasPrefix(p, "/static/") || p == "/federation" || strings.HasPrefix(p, "/federation/")
}

// federate sends the requests of operators who opened a linked console to
// that console.
func (s *Server) federate(next http.Handler) http.Handler {
	if s.hub == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if centralPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		sess := s.loadSession(r)
		if sess == nil || sess.data.Operator == nil || sess.data.Link == "" {
			next.ServeHTTP(w, r)
			return
		}
		upgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
		if upgrade || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			if o := r.Header.Get("Origin"); (o != "" || upgrade) && o != s.origin {
				http.Error(w, tr(langOf(r, sess), "richiesta non valida"), http.StatusForbidden)
				return
			}
		}
		link, ok := s.openLink(r, sess)
		if !ok {
			sess.data.Link = ""
			s.flashTo(w, r, sess, tr(langOf(r, sess), "Il collegamento con la console non è più attivo."), "/federation")
			return
		}
		if r.URL.Path == uploadPath {
			extendDeadlines(w, 30*time.Minute)
		}
		if upgrade {
			s.forwardUpgrade(w, r, sess, link)
			return
		}
		s.forward(w, r, sess, link, r.Method, r.URL.RequestURI(), r.Body, r.Header.Get("Content-Type"), r.ContentLength)
	})
}

// openLink returns the session's open link if the operator may still use it.
func (s *Server) openLink(r *http.Request, sess *session) (store.FederationLink, bool) {
	for _, t := range sess.data.Operator.Tenants {
		if l, err := s.store.GetLink(r.Context(), t, sess.data.Link); err == nil {
			return l, l.Status == store.LinkActive
		}
	}
	return store.FederationLink{}, false
}

// assertion is the central operator as sent to a linked console.
func (s *Server) assertion(r *http.Request, sess *session) string {
	op := sess.data.Operator
	return federation.Operator{ObjectID: op.ObjectID, TenantID: op.TenantID, Name: op.Name, Username: op.Username,
		Roles: op.Roles, Session: sess.data.FedKey, Lang: langOf(r, sess), Theme: sess.data.Theme}.Encode()
}

// forwarded response headers; the security headers are the central
// console's own.
var forwardedHeaders = []string{"Content-Type", "Content-Disposition", "Content-Length", "Location"}

// forward sends one request over a link and relays the answer.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, sess *session, link store.FederationLink,
	method, uri string, body io.Reader, contentType string, length int64) {
	// The host is a constant: the client dials only the link's tunnels.
	out, err := http.NewRequestWithContext(r.Context(), method, federation.URL+localReturn(uri, "/"), body) // #nosec G704 -- see above
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.ContentLength = length
	if contentType != "" {
		out.Header.Set("Content-Type", contentType)
	}
	if v := r.Header.Get("Accept-Language"); v != "" {
		out.Header.Set("Accept-Language", v)
	}
	out.Header.Set(federation.HeaderOperator, s.assertion(r, sess))
	resp, err := s.hub.Client(link.ID).Do(out) // #nosec G704 -- over the link's tunnels only
	if err != nil {
		s.log.Warn("linked console unreachable", "link", link.ID, "err", err)
		s.flashTo(w, r, sess, trf(langOf(r, sess), "La console %s non è raggiungibile in questo momento.", link.Name), "/federation")
		return
	}
	defer resp.Body.Close()
	for _, h := range forwardedHeaders {
		if v := resp.Header.Get(h); v != "" {
			if h == "Location" {
				// Redirects of a linked console stay inside the console.
				v = localReturn(strings.TrimPrefix(v, federation.URL), "/agents")
			}
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		s.log.Debug("relay response", "err", err)
	}
}

// forwardUpgrade relays a WebSocket (interactive shell) to a linked
// console; the upgraded connection then uses one tunnel of the link.
func (s *Server) forwardUpgrade(w http.ResponseWriter, r *http.Request, sess *session, link store.FederationLink) {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			u, _ := url.Parse(federation.URL + localReturn(r.URL.RequestURI(), "/"))
			pr.Out.URL, pr.Out.Host = u, ""
			for _, h := range []string{"Cookie", "Authorization", "X-Forwarded-For", "Forwarded"} {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Set(federation.HeaderOperator, s.assertion(r, sess))
		},
		Transport: s.hub.Client(link.ID).Transport,
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Set-Cookie")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.log.Warn("linked console unreachable", "link", link.ID, "err", err)
			http.Error(w, tr(langOf(r, sess), "La sessione non è disponibile."), http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// ---- federation page ----

type linkView struct {
	store.FederationLink
	Connected int
	Summary   *federation.Summary
}

type federationData struct {
	// Central side.
	Central  bool // links accepted by this console
	LinkAddr string
	Links    []linkView
	Open     string // link open in this session
	Bundle   string // token just created, shown once
	NewName  string
	// Customer side.
	Customer  bool // a central directory is trusted
	Uplink    *store.Uplink
	Up        int
	Issuer    string
	MaxRole   string
	TenantMap string
}

func (s *Server) federationPage(w http.ResponseWriter, r *http.Request, d federationData) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	sess := sessionFrom(r.Context())
	d.Central, d.LinkAddr, d.Open = s.hub != nil, s.linkAddr, sess.data.Link
	if d.Central {
		links, err := s.store.ListLinks(r.Context(), t)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, l := range links {
			v := linkView{FederationLink: l, Connected: s.hub.Connected(l.ID)}
			var sum federation.Summary
			if len(l.Summary) > 0 && json.Unmarshal(l.Summary, &sum) == nil {
				v.Summary = &sum
			}
			d.Links = append(d.Links, v)
		}
	}
	if s.fedVerifier != nil && hasRole(sess.data.Operator, authn.RoleAdmin) {
		d.Customer = true
		cfg := s.fedVerifier.Config()
		d.Issuer, d.MaxRole = cfg.Issuer, cfg.MaxRole
		var maps []string
		for tid, ts := range cfg.TenantMap {
			maps = append(maps, tid+" → "+strings.Join(ts, ", "))
		}
		sort.Strings(maps)
		d.TenantMap = strings.Join(maps, "; ")
		if u, err := s.store.GetUplink(r.Context()); err == nil {
			d.Uplink = &u
			if s.uplink != nil {
				d.Up = s.uplink.Up()
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, err)
			return
		}
	}
	s.render(w, r, "federation", s.T(r, "Console collegate"), d)
}

func (s *Server) handleFederation(w http.ResponseWriter, r *http.Request) {
	s.federationPage(w, r, federationData{})
}

var linkNameRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} .,&'()-]{0,79}$`)

// handleCreateLink creates a link and shows its token once.
func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok || s.hub == nil {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !linkNameRe.MatchString(name) {
		s.flash(w, r, s.T(r, "Nome non valido."), "/federation")
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	token := ids.NewSecret(32)
	exp := s.now().Add(federation.TokenTTL)
	l := store.FederationLink{ID: ids.NewUUID(), TenantID: t, Name: name, TokenExpiresAt: &exp, CreatedBy: "operator:" + op.Username}
	switch err := s.store.CreateLink(r.Context(), l, store.HashToken(token)); {
	case errors.Is(err, store.ErrLinkExists):
		s.flash(w, r, s.T(r, "Esiste già un collegamento con questo nome."), "/federation")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), t, op, "federation.link_created", l.ID, map[string]any{"name": name, "expires_at": exp})
	bundle := federation.Bundle{Addr: s.linkAddr, Fingerprint: s.hub.ID.Fingerprint, Token: token}.Encode()
	s.federationPage(w, r, federationData{Bundle: bundle, NewName: name})
}

func (s *Server) handleRevokeLink(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || s.hub == nil || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	l, err := s.store.GetLink(r.Context(), t, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.store.RevokeLink(r.Context(), t, id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.hub.Drop(id)
	s.audit(r.Context(), t, sessionFrom(r.Context()).data.Operator, "federation.link_revoked", id, map[string]any{"name": l.Name})
	s.flash(w, r, s.Tf(r, "Collegamento con %s revocato.", l.Name), "/federation")
}

// handleOpenLink makes the next pages those of a linked console.
func (s *Server) handleOpenLink(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	t, ok := tenantOf(r)
	id := r.PostFormValue("link")
	if !ok || s.hub == nil || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	l, err := s.store.GetLink(r.Context(), t, id)
	if err != nil || l.Status != store.LinkActive {
		http.NotFound(w, r)
		return
	}
	sess.data.Link = l.ID
	if sess.data.FedKey == "" {
		sess.data.FedKey = ids.NewSecret(32)
	}
	s.audit(r.Context(), t, sess.data.Operator, "federation.link_opened", l.ID, map[string]any{"name": l.Name})
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/agents", http.StatusSeeOther)
}

func (s *Server) handleCloseLink(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	sess.data.Link = ""
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/federation", http.StatusSeeOther)
}

// ---- step-up for a linked console ----

var opaqueRe = regexp.MustCompile(`^[A-Za-z0-9._-]{16,128}$`)

// handleFedStepUp signs the operator in again, with MFA, for an approval
// pending on the open linked console; the nonce binds the sign-in to that
// console's request.
func (s *Server) handleFedStepUp(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	q := r.URL.Query()
	if sess.data.Link == "" || !opaqueRe.MatchString(q.Get("state")) || !opaqueRe.MatchString(q.Get("nonce")) {
		http.Error(w, s.T(r, "richiesta non valida"), http.StatusBadRequest)
		return
	}
	f := &fedStepUp{Link: sess.data.Link, State: q.Get("state"), Nonce: q.Get("nonce"),
		CodeVerifier: oauth2.GenerateVerifier(), StartedAt: s.now()}
	sess.data.FedStepUp = f
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	p := &Pending{Nonce: f.Nonce, CodeVerifier: f.CodeVerifier}
	opts := append(s.authOptions(p, true), oauth2.SetAuthURLParam("login_hint", sess.data.Operator.Username))
	http.Redirect(w, r, s.oauth.AuthCodeURL(f.State, opts...), http.StatusSeeOther) // #nosec G710 -- the identity provider's endpoint; state and nonce are escaped parameters
}

// completeFedStepUp verifies the sign-in and hands the id_token to the
// linked console, which verifies it again and passes it to its signer.
func (s *Server) completeFedStepUp(w http.ResponseWriter, r *http.Request, sess *session) {
	f := sess.data.FedStepUp
	lang := langOf(r, sess)
	sess.data.FedStepUp = nil
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, trf(lang, "accesso non riuscito: %s", e), http.StatusUnauthorized)
		return
	}
	if s.now().Sub(f.StartedAt) > pendingMaxAge || f.Link != sess.data.Link {
		http.Error(w, tr(lang, "accesso non valido o scaduto: riprova"), http.StatusBadRequest)
		return
	}
	raw, err := s.exchange(r.Context(), q.Get("code"), f.CodeVerifier)
	if err != nil {
		s.log.Warn("token exchange failed", "err", err)
		http.Error(w, tr(lang, "accesso non riuscito"), http.StatusUnauthorized)
		return
	}
	c, err := s.verifier.Verify(r.Context(), raw)
	op := sess.data.Operator
	if err != nil || c.Nonce != f.Nonce || c.ObjectID != op.ObjectID || c.TenantID != op.TenantID {
		s.log.Warn("step-up for a linked console refused", "err", err)
		http.Error(w, tr(lang, "l'approvazione deve essere fatta dallo stesso operatore"), http.StatusForbidden)
		return
	}
	link, ok := s.openLink(r, sess)
	if !ok {
		http.Error(w, tr(lang, "Il collegamento con la console non è più attivo."), http.StatusForbidden)
		return
	}
	form := url.Values{"state": {f.State}, "id_token": {raw}}.Encode()
	s.forward(w, r, sess, link, http.MethodPost, federation.PathCallback, strings.NewReader(form),
		"application/x-www-form-urlencoded", int64(len(form)))
}

// ---- customer side ----

type fedSessionKey struct{}

// fedSessionID derives the session of a central operator from the central
// session's random key: one customer session per central session.
func fedSessionID(key string) string {
	sum := sha256.Sum256([]byte("openrmm/federation-session\x00" + key))
	return hex.EncodeToString(sum[:])
}

// LinkHandler serves the central console over the link: the normal console
// for central operators, plus the summary and the step-up callback. The
// link's own settings are never reachable this way.
func (s *Server) LinkHandler() http.Handler {
	app := s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.fedVerifier == nil {
			http.Error(w, "federation is not configured on this console", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == federation.PathSummary {
			s.handleFedSummary(w, r)
			return
		}
		a, err := federation.ParseOperator(r.Header.Get(federation.HeaderOperator))
		if err != nil {
			http.Error(w, "invalid operator", http.StatusForbidden)
			return
		}
		tenants := s.fedVerifier.Config().TenantMap[a.TenantID]
		roles := s.fedVerifier.CapRoles(a.Roles)
		op := &Operator{ObjectID: a.ObjectID, TenantID: a.TenantID, Name: a.Name, Username: a.Username,
			Roles: roles, Tenants: tenants, Federated: true}
		if len(tenants) == 0 || !hasRole(op, authn.RoleReader) {
			s.log.Warn("central operator refused", "operator", a.Username, "tid", a.TenantID)
			http.Error(w, tr(a.Lang, "accesso negato: directory non autorizzata"), http.StatusForbidden)
			return
		}
		if r.URL.Path == "/federation" || strings.HasPrefix(r.URL.Path, "/federation/") {
			http.Error(w, tr(a.Lang, "Il collegamento si gestisce solo dalla console del cliente."), http.StatusForbidden)
			return
		}
		sess, err := s.fedSession(r.Context(), a, op)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if r.URL.Path == federation.PathCallback && r.Method == http.MethodPost {
			s.handleFedCallback(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)), sess)
			return
		}
		app.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), fedSessionKey{}, sess)))
	})
}

// fedSession loads or creates the session of a central operator, with the
// identity, roles and preferences of this request.
func (s *Server) fedSession(ctx context.Context, a federation.Operator, op *Operator) (*session, error) {
	id := fedSessionID(a.Session)
	sess := &session{id: id}
	ws, err := s.store.GetSession(ctx, id, s.now())
	reuse := err == nil && json.Unmarshal(ws.Data, &sess.data) == nil && sess.data.Operator != nil &&
		sess.data.Operator.ObjectID == op.ObjectID && s.now().Sub(sess.data.CreatedAt) <= absoluteMaxAge
	if !reuse {
		sess.data = SessionData{CSRF: ids.NewSecret(32), CreatedAt: s.now()}
		for _, t := range op.Tenants {
			s.audit(ctx, t, op, "operator.login", op.ObjectID, map[string]any{"roles": op.Roles, "via": "central console"})
		}
	}
	sess.data.Operator = op
	if !slices.Contains(op.Tenants, sess.data.Tenant) {
		sess.data.Tenant = op.Tenants[0]
	}
	if slices.Contains(languages, a.Lang) {
		sess.data.Lang = a.Lang
	}
	if a.Theme == "" || a.Theme == "light" || a.Theme == "dark" || a.Theme == "auto" {
		sess.data.Theme = a.Theme
	}
	return sess, nil
}

// redirectStepUp sends an approval to the identity provider, or for a
// central operator to the central console, which signs in with its own
// directory and calls back over the link.
func (s *Server) redirectStepUp(w http.ResponseWriter, r *http.Request, sess *session, p *Pending) {
	if sess.data.Operator.Federated {
		http.Redirect(w, r, "/federation/stepup?"+url.Values{"state": {p.State}, "nonce": {p.Nonce}}.Encode(), http.StatusSeeOther)
		return
	}
	opts := append(s.authOptions(p, true), oauth2.SetAuthURLParam("login_hint", sess.data.Operator.Username))
	http.Redirect(w, r, s.oauth.AuthCodeURL(p.State, opts...), http.StatusSeeOther)
}

// handleFedCallback completes an approval with the id_token of the central
// operator, verified against the trusted central directory.
func (s *Server) handleFedCallback(w http.ResponseWriter, r *http.Request, sess *session) {
	lang := langOf(r, sess)
	p := sess.data.Pending
	if p == nil || r.PostFormValue("state") != p.State || s.now().Sub(p.StartedAt) > pendingMaxAge {
		http.Error(w, tr(lang, "accesso non valido o scaduto: riprova"), http.StatusBadRequest)
		return
	}
	sess.data.Pending = nil // single use
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	raw := r.PostFormValue("id_token")
	c, err := s.fedVerifier.Verify(r.Context(), raw)
	if err != nil {
		s.log.Warn("central operator token rejected", "err", err)
		http.Error(w, tr(lang, "accesso negato"), http.StatusForbidden)
		return
	}
	switch p.Purpose {
	case "job":
		s.completeJob(w, r, sess, p, c, raw)
	case "policy":
		s.completePolicy(w, r, sess, p, c, raw)
	case "installer":
		s.completeInstaller(w, r, sess, p, c, s.fedVerifier)
	default:
		http.Error(w, tr(lang, "accesso non valido"), http.StatusBadRequest)
	}
}

// handleFedSummary reports this console's state for the central dashboard.
func (s *Server) handleFedSummary(w http.ResponseWriter, r *http.Request) {
	var tenant string
	for _, ts := range s.fedVerifier.Config().TenantMap {
		if len(ts) > 0 && (tenant == "" || ts[0] < tenant) {
			tenant = ts[0]
		}
	}
	ctx := r.Context()
	sum := federation.Summary{GeneratedAt: s.now().UTC()}
	if t, err := s.store.GetTenant(ctx, tenant); err == nil {
		sum.Console = t.Name
	}
	agents, err := s.store.ListAgents(ctx, tenant)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, a := range agents {
		switch a.Status {
		case store.AgentActive:
			sum.Agents++
			if s.online(a) {
				sum.Online++
			}
		case store.AgentPending:
			sum.Pending++
		}
	}
	if open, err := s.store.ListAlerts(ctx, tenant, "", true, 5000); err == nil {
		sum.OpenAlerts = len(open)
		for _, a := range open {
			if a.Severity == "critical" {
				sum.Critical++
			}
		}
	}
	if sts, err := s.store.ListUpdateStatus(ctx, tenant, ""); err == nil {
		for _, st := range sts {
			if st.Source != updates.SourceWindows {
				continue
			}
			if st.Important > 0 {
				sum.MissingSec++
			}
			if st.Reboot {
				sum.Reboot++
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sum)
}

// ---- customer: link settings (local administrators only) ----

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	if s.fedVerifier == nil {
		http.NotFound(w, r)
		return
	}
	t, _ := tenantOf(r)
	op := sessionFrom(r.Context()).data.Operator
	if _, err := s.store.GetUplink(r.Context()); err == nil {
		s.flash(w, r, s.T(r, "Questa console è già collegata: rimuovi prima il collegamento attuale."), "/federation")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	u, err := federation.Join(ctx, r.PostFormValue("bundle"), "operator:"+op.Username, s.now())
	if err != nil {
		s.log.Warn("federation join failed", "err", err)
		s.flash(w, r, s.Tf(r, "Collegamento non riuscito: %v", err), "/federation")
		return
	}
	if err := s.store.PutUplink(r.Context(), u); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.uplink != nil {
		s.uplink.Sync(context.WithoutCancel(r.Context()))
	}
	s.audit(r.Context(), t, op, "federation.joined", u.LinkID, map[string]any{"central": u.CentralAddr, "fingerprint": u.CentralFingerprint})
	s.flash(w, r, s.T(r, "Console collegata alla console centrale."), "/federation")
}

// handleUplinkState suspends, resumes or removes the link.
func (s *Server) handleUplinkState(w http.ResponseWriter, r *http.Request) {
	if s.fedVerifier == nil {
		http.NotFound(w, r)
		return
	}
	t, _ := tenantOf(r)
	op := sessionFrom(r.Context()).data.Operator
	var err error
	action, msg := r.PathValue("action"), ""
	switch action {
	case "suspend":
		err, msg = s.store.SetUplinkSuspended(r.Context(), true), s.T(r, "Collegamento sospeso: la console centrale non può più operare qui.")
	case "resume":
		err, msg = s.store.SetUplinkSuspended(r.Context(), false), s.T(r, "Collegamento ripreso.")
	case "leave":
		err, msg = s.store.DeleteUplink(r.Context()), s.T(r, "Collegamento rimosso.")
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	if s.uplink != nil {
		s.uplink.Sync(context.WithoutCancel(r.Context()))
	}
	s.audit(r.Context(), t, op, "federation."+action, "", nil)
	s.flash(w, r, msg, "/federation")
}
