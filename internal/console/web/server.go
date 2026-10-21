// Package web is the operator console: server-rendered pages, no third-party
// JavaScript, a strict Content Security Policy, Entra ID login with MFA, and
// a step-up authentication bound to every job an operator runs.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/authn"
	"github.com/stefanozanarini/open-rmm/internal/console/pkgfiles"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/wingetcat"
	"github.com/stefanozanarini/open-rmm/internal/federation"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Config configures the console.
type Config struct {
	Store    store.Store
	Verifier *authn.Verifier
	Signer   openrmmv1.SignerServiceClient
	Logger   *slog.Logger
	// PublicURL is the console URL as seen by browsers, e.g.
	// https://console.example.com (also the base of the redirect URI).
	PublicURL    string
	ClientSecret string
	Now          func() time.Time
	// HTTPClient is used for the token exchange (tests).
	HTTPClient *http.Client
	// Packages is the package file store (shared with the core).
	Packages pkgfiles.Dir
	// Winget reads the winget catalog; nil means the public repository.
	Winget *wingetcat.Client
	// Federation, central side: Hub accepts the links of customer consoles;
	// LinkAddr is the address they dial (put in link tokens).
	Hub      *federation.Hub
	LinkAddr string
	// Federation, customer side: FedVerifier verifies the operators of the
	// trusted central console (nil: links carry nothing); Uplink runs the
	// link.
	FedVerifier *authn.Verifier
	Uplink      *federation.Uplink
	// Shell reaches the interactive shell sessions held by the core (nil:
	// shells are not available).
	Shell openrmmv1.ShellBrokerServiceClient
	// Builder signs and builds agent installers preconfigured with
	// AgentInstall (nil: not available).
	Builder      openrmmv1.BuilderServiceClient
	AgentInstall AgentInstall
	// AgentBundle and ModuleBundle: the agent and the modules shipped with
	// the console.
	AgentBundle  AgentBundle
	ModuleBundle ModuleBundle
	// ConsoleAdminDirs are the Entra directories (tid) whose Admins manage
	// console-wide settings; empty: the only directory of the tenant map.
	ConsoleAdminDirs []string
}

// Server serves the console.
type Server struct {
	store    store.Store
	verifier *authn.Verifier
	signer   openrmmv1.SignerServiceClient
	log      *slog.Logger
	oauth    oauth2.Config
	origin   string
	idpHost  string
	now      func() time.Time
	client   *http.Client
	pages    map[string]map[string]*template.Template // language, page
	packages pkgfiles.Dir
	winget   *wingetcat.Client
	ad       adCache

	hub          *federation.Hub
	linkAddr     string
	fedVerifier  *authn.Verifier
	uplink       *federation.Uplink
	shell        openrmmv1.ShellBrokerServiceClient
	builder      openrmmv1.BuilderServiceClient
	agentInstall AgentInstall
	bundle       AgentBundle
	modules      ModuleBundle
	// consoleAdminDirs: see Config.ConsoleAdminDirs.
	consoleAdminDirs []string
}

// New returns a Server.
func New(cfg Config) (*Server, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") || u.Host == "" {
		return nil, errors.New("PublicURL must be an https URL")
	}
	authURL, err := url.Parse(cfg.Verifier.Provider.Endpoint().AuthURL)
	if err != nil {
		return nil, err
	}
	if cfg.Winget == nil {
		cfg.Winget = wingetcat.New()
	}
	s := &Server{
		store: cfg.Store, verifier: cfg.Verifier, signer: cfg.Signer, log: cfg.Logger,
		packages: cfg.Packages, winget: cfg.Winget,
		hub: cfg.Hub, linkAddr: cfg.LinkAddr, fedVerifier: cfg.FedVerifier, uplink: cfg.Uplink, shell: cfg.Shell,
		builder: cfg.Builder, agentInstall: cfg.AgentInstall, bundle: cfg.AgentBundle, modules: cfg.ModuleBundle, consoleAdminDirs: cfg.ConsoleAdminDirs,
		origin: u.Scheme + "://" + u.Host, idpHost: authURL.Scheme + "://" + authURL.Host,
		now: cfg.Now, client: cfg.HTTPClient,
		oauth: oauth2.Config{
			ClientID:     cfg.Verifier.Config().ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     cfg.Verifier.Provider.Endpoint(),
			RedirectURL:  strings.TrimSuffix(cfg.PublicURL, "/") + "/auth/callback",
			Scopes:       []string{"openid", "profile", "email"},
		},
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

// funcs are the template functions for a language.
func funcs(lang string) template.FuncMap {
	timeFmt := dateFormat(lang) + " 15:04:05"
	return template.FuncMap{
		"t":  func(key string) string { return tr(lang, key) },
		"tf": func(key string, args ...any) string { return trf(lang, key, args...) },
		"th": func(key string) template.HTML { return trHTML(lang, key) },
		"fmtTime": func(t any) string {
			switch v := t.(type) {
			case time.Time:
				if v.IsZero() {
					return "-"
				}
				return v.Local().Format(timeFmt)
			case *time.Time:
				if v == nil {
					return "-"
				}
				return v.Local().Format(timeFmt)
			}
			return "-"
		},
		"label": func(v any) string {
			if l, ok := labels[fmt.Sprint(v)]; ok {
				return tr(lang, l)
			}
			return fmt.Sprint(v)
		},
		"bytes": func(n int64) string {
			if n <= 0 {
				return "-"
			}
			return inventory.Bytes(n)
		},
		"pctFree": func(free, size int64) int {
			if size <= 0 {
				return 0
			}
			return int(100 * free / size)
		},
		"isoDate": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return "-"
			}
			return t.Local().Format(dateFormat(lang) + " 15:04")
		},
		"yesNo": func(b *bool) string {
			switch {
			case b == nil:
				return "-"
			case *b:
				return tr(lang, "sì")
			}
			return "no"
		},
		// alertCtx passes the page (for CSRF and roles) to the alert rows.
		"alertCtx": func(p page, alerts []alertView, ret string) map[string]any {
			return map[string]any{"Alerts": alerts, "CSRF": p.CSRF, "CanRun": p.CanRun, "Return": ret}
		},
		"logonType": func(t int) string {
			if l, ok := logonTypes[t]; ok {
				return tr(lang, l)
			}
			return fmt.Sprint(t)
		},
		// panelCtx shows an agent's sections inside the agent list.
		"panelCtx":   func(p page, d *agentData) page { p.Data = d; return p },
		"rowLink":    rowLink,
		"rowTab":     rowTabLink,
		"maxHistory": func() int { return maxHistoryRows },
		"rowsCtx": func(d agentsData, rows []agentRow, sel bool) map[string]any {
			return map[string]any{"Rows": rows, "Select": sel, "View": d}
		},
		// qs builds a query string from key/value pairs, skipping empty values.
		"qs": func(kv ...string) string {
			v := url.Values{}
			for i := 0; i+1 < len(kv); i += 2 {
				if kv[i+1] != "" {
					v.Set(kv[i], kv[i+1])
				}
			}
			if len(v) == 0 {
				return ""
			}
			return "?" + v.Encode()
		},
		"short": func(s string) string {
			if len(s) > 8 {
				return s[:8]
			}
			return s
		},
	}
}

// parseTemplates parses every page once per language, since the template
// functions are bound at parse time.
func (s *Server) parseTemplates() error {
	names, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	s.pages = map[string]map[string]*template.Template{}
	for _, lang := range languages {
		s.pages[lang] = map[string]*template.Template{}
		for _, n := range names {
			base := strings.TrimSuffix(strings.TrimPrefix(n, "templates/"), ".html")
			if base == "layout" || strings.HasPrefix(base, "_") {
				continue
			}
			// Shared sections (templates/_*.html) come before the page, which
			// may redefine them.
			t, err := template.New("layout.html").Funcs(funcs(lang)).ParseFS(assets, "templates/layout.html", "templates/_*.html", n)
			if err != nil {
				return fmt.Errorf("template %s: %w", n, err)
			}
			s.pages[lang][base] = t
		}
	}
	return nil
}

// Handler returns the HTTP handler with all routes and middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.Handle("POST /logout", s.auth(s.handleLogout))

	mux.Handle("GET /{$}", s.auth(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/agents", http.StatusSeeOther) }))
	mux.Handle("POST /tenant", s.auth(s.handleSelectTenant))
	mux.Handle("GET /agents", s.auth(s.handleAgents))
	mux.Handle("GET /agents/{id}", s.auth(s.handleAgent))
	mux.Handle("POST /agents/{id}/approve", s.role(authn.RoleAdmin, s.handleApprove))
	mux.Handle("POST /agents/approve", s.role(authn.RoleAdmin, s.handleApproveMany))
	mux.Handle("POST /agents/{id}/revoke", s.role(authn.RoleAdmin, s.handleRevoke))
	mux.Handle("POST /agents/{id}/jobs", s.role(authn.RoleOperator, s.handleRunJob))
	mux.Handle("POST /agents/{id}/collect", s.role(authn.RoleOperator, s.handleCollect))
	mux.Handle("POST /agents/{id}/ad-reader", s.role(authn.RoleAdmin, s.handleADReader))
	mux.Handle("POST /agents/{id}/ring", s.role(authn.RoleAdmin, s.handleSetRing))
	mux.Handle("POST /agents/ring", s.role(authn.RoleAdmin, s.handleSetRing))
	mux.Handle("POST /agents/{id}/firmware", s.role(authn.RoleOperator, s.handleFirmwareInstall))
	mux.Handle("POST /agents/{id}/shell", s.role(authn.RoleOperator, s.handleOpenShell))
	mux.Handle("GET /shell/{id}", s.role(authn.RoleOperator, s.handleShellPage))
	mux.Handle("GET /shell/{id}/ws", s.role(authn.RoleOperator, s.handleShellSocket))
	mux.Handle("GET /jobs", s.auth(s.handleJobs))
	mux.Handle("GET /jobs/{id}", s.auth(s.handleJob))
	mux.Handle("GET /modules", s.auth(s.handleModules))
	mux.Handle("GET /updates", s.auth(s.handleUpdates))
	mux.Handle("POST /updates/target", s.role(authn.RoleAdmin, s.handleSetTarget))
	mux.Handle("POST /updates/auto-pilot", s.role(authn.RoleAdmin, s.handleAutoPilot))
	mux.Handle("GET /reports", s.auth(s.handleReports))
	mux.Handle("GET /tokens", s.role(authn.RoleAdmin, s.handleTokens))
	mux.Handle("POST /tokens", s.role(authn.RoleAdmin, s.handleCreateToken))
	mux.Handle("POST /tokens/{id}/revoke", s.role(authn.RoleAdmin, s.handleRevokeToken))
	mux.Handle("GET /audit", s.auth(s.handleAudit))
	mux.Handle("GET /alerts", s.auth(s.handleAlerts))
	mux.Handle("GET /patches", s.auth(s.handlePatches))
	mux.Handle("GET /packages", s.auth(s.handlePackages))
	mux.Handle("POST "+uploadPath, s.role(authn.RoleAdmin, s.handleUpload))
	mux.Handle("GET /packages/{sha}/deploy", s.role(authn.RoleOperator, s.handleDeployForm))
	mux.Handle("POST /packages/{sha}/deploy", s.role(authn.RoleOperator, s.handleDeploy))
	mux.Handle("POST /catalog", s.role(authn.RoleAdmin, s.handleAddCatalog))
	mux.Handle("POST /packages/{sha}/unsigned", s.role(authn.RoleAdmin, s.handleSetUnsigned))
	mux.Handle("POST /catalog/refresh", s.role(authn.RoleAdmin, s.handleRefreshCatalog))
	mux.Handle("POST /catalog/{id}/match", s.role(authn.RoleAdmin, s.handleCatalogMatch))
	mux.Handle("POST /catalog/{id}/import", s.role(authn.RoleAdmin, s.handleImportCatalog))
	mux.Handle("POST /agents/{id}/uninstall", s.role(authn.RoleOperator, s.handleUninstall))
	mux.Handle("POST /agents/{id}/notes", s.role(authn.RoleOperator, s.handleAddNote))
	mux.Handle("POST /agents/{id}/site", s.role(authn.RoleOperator, s.handleMoveAgents))
	mux.Handle("POST /agents/site", s.role(authn.RoleOperator, s.handleMoveAgents))
	mux.Handle("GET /agents/bulk", s.role(authn.RoleOperator, s.handleBulkForm))
	mux.Handle("POST /agents/bulk", s.role(authn.RoleOperator, s.handleBulkJobs))
	mux.Handle("GET /sites", s.auth(s.handleSites))
	mux.Handle("POST /sites", s.role(authn.RoleAdmin, s.handleSaveSite))
	mux.Handle("POST /theme", s.auth(s.handleTheme))
	mux.Handle("POST /lang", s.auth(s.handleLang))
	mux.Handle("GET /ad", s.auth(s.handleAD))
	mux.Handle("GET /setup", s.role(authn.RoleAdmin, s.handleSetup))
	mux.Handle("POST /setup/codesign", s.role(authn.RoleAdmin, s.handleSaveCodeSigning))
	mux.Handle("GET /setup/{file}", s.auth(s.handleCodeSigningCert))
	mux.Handle("POST /alerts/{id}/ack", s.role(authn.RoleOperator, s.handleAckAlert))
	mux.Handle("GET /settings", s.role(authn.RoleAdmin, s.handleSettings))
	mux.Handle("POST /settings", s.role(authn.RoleAdmin, s.handleSaveSettings))
	mux.Handle("POST /settings/logo", s.role(authn.RoleAdmin, s.handleLogoUpload))
	mux.Handle("GET /logo", s.auth(s.handleLogo))
	mux.Handle("GET /policies", s.auth(s.handlePolicies))
	mux.Handle("GET /policies/new", s.role(authn.RoleAdmin, s.handlePolicyForm))
	mux.Handle("GET /policies/{id}", s.role(authn.RoleAdmin, s.handlePolicyForm))
	mux.Handle("POST /policies", s.role(authn.RoleAdmin, s.handleSavePolicy))
	mux.Handle("POST /policies/{id}/delete", s.role(authn.RoleAdmin, s.handleDeletePolicy))
	mux.Handle("GET /agent-installer", s.role(authn.RoleOperator, s.handleInstallers))
	mux.Handle("POST /agent-installer/build", s.role(authn.RoleAdmin, s.handleBuildInstaller))
	mux.Handle("POST /agent-installer/confirm", s.role(authn.RoleAdmin, s.handleConfirmInstaller))
	mux.Handle("GET /agent-installer/{id}/msi", s.role(authn.RoleOperator, s.handleDownloadInstaller))
	mux.Handle("POST /agent-installer/signing/ca", s.console(s.handleCreateSigningCA))
	mux.Handle("POST /agent-installer/signing/request", s.console(s.handleCreateSigningRequest))
	mux.Handle("GET /agent-installer/signing/request.csr", s.console(s.handleSigningRequestFile))
	mux.Handle("POST /agent-installer/signing/certificate", s.console(s.handleImportSigningCert))
	mux.Handle("POST /agent-installer/signing/pfx", s.console(s.handleImportSigningPFX))
	mux.Handle("POST /agent-installer/signing/renew", s.console(s.handleRenewSigning))
	mux.Handle("POST /agent-installer/signing/keys", s.console(s.handleCreateReleaseKeys))
	mux.Handle("POST /modules/publish", s.console(s.startPublish(modulesKind)))
	mux.Handle("POST "+publishModulePath, s.console(s.handlePublishModule))
	mux.Handle("POST /modules/publish/bundled", s.console(s.handlePublishBundledModules))
	mux.Handle("POST /updates/publish", s.console(s.startPublish(releasesKind)))
	mux.Handle("POST "+publishReleasePath, s.console(s.handlePublishRelease))
	mux.Handle("GET /federation", s.auth(s.handleFederation))
	mux.Handle("POST /federation/links", s.role(authn.RoleAdmin, s.handleCreateLink))
	mux.Handle("POST /federation/links/{id}/revoke", s.role(authn.RoleAdmin, s.handleRevokeLink))
	mux.Handle("POST /federation/open", s.auth(s.handleOpenLink))
	mux.Handle("POST /federation/close", s.auth(s.handleCloseLink))
	mux.Handle("GET /federation/stepup", s.role(authn.RoleOperator, s.handleFedStepUp))
	mux.Handle("POST /federation/join", s.role(authn.RoleAdmin, s.handleJoin))
	mux.Handle("POST /federation/uplink/{action}", s.role(authn.RoleAdmin, s.handleUplinkState))
	return s.secure(s.federate(mux))
}

// secure sets the security headers on every response.
func (s *Server) secure(next http.Handler) http.Handler {
	// Scripts only from the console's own static files, never inline.
	csp := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; form-action 'self' " + s.idpHost +
		"; frame-ancestors 'none'; base-uri 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin, not no-referrer: with no-referrer browsers send
		// "Origin: null" on form posts, which the CSRF check must refuse.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if strings.HasPrefix(s.origin, "https://") {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		// Bound request bodies: forms are small, scripts at most 1 MB;
		// uploads are bounded by their handler.
		limit := int64(2 << 20)
		if l, ok := streamedUploads[r.URL.Path]; ok {
			limit = l
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		// A panic becomes a clean 500 instead of a dropped connection (which
		// clients may silently retry, replaying a one-time step).
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic serving request", "path", r.URL.Path, "panic", v)
				http.Error(w, s.T(r, "errore interno"), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type ctxHandler func(http.ResponseWriter, *http.Request)

// auth requires an authenticated session; POSTs also need a valid CSRF token.
func (s *Server) auth(h ctxHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := s.loadSession(r)
		if sess == nil || sess.data.Operator == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, tr(langOf(r, sess), "sessione scaduta"), http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			if err := s.checkCSRF(r, sess); err != nil {
				http.Error(w, tr(langOf(r, sess), "richiesta non valida"), http.StatusForbidden)
				return
			}
		}
		// Refresh the idle timeout.
		if err := s.save(r.Context(), w, sess); err != nil {
			s.fail(w, r, err)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	})
}

// role requires one of the given roles; Admin implies Operator and Reader.
func (s *Server) role(role string, h ctxHandler) http.Handler {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		op := sessionFrom(r.Context()).data.Operator
		if !hasRole(op, role) {
			s.log.Warn("forbidden", "operator", op.Username, "path", r.URL.Path, "needs", role)
			http.Error(w, s.T(r, "permesso negato"), http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

func hasRole(op *Operator, role string) bool {
	for _, r := range op.Roles {
		if r == role || r == authn.RoleAdmin || (role == authn.RoleReader && r == authn.RoleOperator) {
			return true
		}
	}
	return false
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "err", err)
	http.Error(w, s.T(r, "errore interno"), http.StatusInternalServerError)
}

// page is the data every template receives.
type page struct {
	Title    string
	Operator *Operator
	CSRF     string
	Tenant   store.Tenant
	Tenants  []store.Tenant
	Flash    string
	IsAdmin  bool
	CanRun   bool
	Data     any
	Refresh  int
	// OpenAlerts is shown in the navigation.
	OpenAlerts int
	// Theme is the operator's choice: "" (the default, dark), light, dark
	// or auto (follows the browser).
	Theme string
	Lang  string
	Path  string
	// Federation: Federated when a central console's operator works on
	// this console; ShowLinks shows the linked consoles page in the menu.
	Federated bool
	ShowLinks bool
	// HasLogo: the tenant has a company logo (served at /logo).
	HasLogo bool
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	sess := sessionFrom(r.Context())
	lang := langOf(r, sess)
	p := page{Title: title, Data: data, Lang: lang}
	if sess != nil && sess.data.Operator != nil {
		op := sess.data.Operator
		p.Operator, p.CSRF, p.Flash, p.Theme = op, sess.data.CSRF, sess.data.Flash, sess.data.Theme
		p.Path = r.URL.RequestURI()
		p.IsAdmin, p.CanRun = hasRole(op, authn.RoleAdmin), hasRole(op, authn.RoleOperator)
		p.Federated = op.Federated
		p.ShowLinks = !op.Federated && (s.hub != nil || (s.fedVerifier != nil && p.IsAdmin))
		for _, id := range op.Tenants {
			if t, err := s.store.GetTenant(r.Context(), id); err == nil {
				p.Tenants = append(p.Tenants, t)
				if id == sess.data.Tenant {
					p.Tenant = t
				}
			}
		}
		if sess.data.Tenant != "" {
			if open, err := s.store.ListAlerts(r.Context(), sess.data.Tenant, "", true, 1000); err == nil {
				p.OpenAlerts = len(open)
			}
			if st, err := s.store.GetSettings(r.Context(), sess.data.Tenant); err == nil {
				p.HasLogo = len(st.Logo) > 0
			}
		}
		if sess.data.Flash != "" {
			sess.data.Flash = ""
			_ = s.save(r.Context(), w, sess)
		}
	}
	if v, ok := data.(interface{ refresh() int }); ok {
		p.Refresh = v.refresh()
	}
	t := s.pages[lang][name]
	if t == nil {
		s.fail(w, r, fmt.Errorf("no template %s", name))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, p); err != nil {
		s.log.Error("render", "template", name, "err", err)
	}
}

// flash stores a one-time message in the request's session and redirects.
func (s *Server) flash(w http.ResponseWriter, r *http.Request, msg, to string) {
	s.flashTo(w, r, sessionFrom(r.Context()), msg, to)
}

// flashTo is flash with an explicit session, for handlers outside the auth
// middleware (the identity provider callback).
func (s *Server) flashTo(w http.ResponseWriter, r *http.Request, sess *session, msg, to string) {
	to = localReturn(to, "/agents")
	if sess == nil {
		http.Redirect(w, r, to, http.StatusSeeOther) // #nosec G710 -- local path (localReturn)
		return
	}
	sess.data.Flash = msg
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther) // #nosec G710 -- local path (localReturn)
}

// logonTypes names the Windows logon types.
var logonTypes = map[int]string{2: "interattivo", 3: "rete", 4: "batch", 5: "servizio", 7: "sblocco",
	8: "rete (testo in chiaro)", 9: "nuove credenziali", 10: "desktop remoto", 11: "credenziali in cache"}

// labels names the states shown in the UI, in Italian (see catalogEN).
var labels = map[string]string{
	"pending": "in attesa", "active": "attivo", "revoked": "revocato", "online": "online",
	"queued": "in coda", "sent": "inviato", "accepted": "accettato", "running": "in esecuzione",
	"succeeded": "completato", "failed": "fallito", "rejected": "rifiutato", "expired": "scaduto",
	"downloading": "download", "staged": "pronto", "applied": "installato", "rolled_back": "ripristinato",
	"all": "tutti", "clients": "solo client", "servers": "solo server", "client": "client", "server": "server", "unknown": "non noto",
	"on": "attivo", "off": "non attivo", "suspended": "sospeso", "encrypting": "cifratura in corso", "decrypting": "decifratura in corso",
	"machine": "computer", "user": "utente", "laptop": "portatile", "desktop": "desktop", "all-in-one": "all-in-one",
	"mini-pc": "mini PC", "tablet": "tablet",
	"application": "applicazione", "other": "altro", "recommended": "consigliato", "optional": "facoltativo",
	"software.added": "software installato", "software.removed": "software rimosso", "software.updated": "software aggiornato",
	"hardware": "hardware", "os": "sistema operativo", "firmware": "firmware", "disk.health": "stato disco",
	"encryption": "cifratura", "remote_access": "accesso remoto",
	"warning": "attenzione", "failing": "errore", "critical": "critica", "info": "informazione", "ok": "ok",
	"check.failing": "controllo non superato", "rdp.outside_lan": "RDP fuori dalle reti consentite",
	"rdp.new_source": "RDP da indirizzo nuovo", "logon.failures": "accessi falliti ripetuti",
	"logon.spray": "password spraying", "account.lockout": "account bloccato", "logon.truncated": "eventi troncati",
	"logon": "accesso", "security": "sicurezza", "rollup": "cumulativo", "update": "aggiornamento",
	"definition": "definizioni", "feature_pack": "feature pack", "service_pack": "service pack", "upgrade": "nuova versione",
	"tools": "strumenti", "driver": "driver", "wsus": "WSUS", "intune": "Intune", "none": "open-rmm",
	"windows_update": "Windows Update", "component_servicing": "componenti di Windows", "file_rename": "file da sostituire", "logon_failed": "accesso fallito", "lockout": "blocco account", "rdp_auth": "autenticazione RDP",
	"rdp_session_logon": "sessione RDP", "rdp_disconnect": "RDP disconnesso", "rdp_reconnect": "RDP riconnesso",
}
