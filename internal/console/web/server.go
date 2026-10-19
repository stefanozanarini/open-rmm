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
	"github.com/stefanozanarini/open-rmm/internal/console/store"
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
	pages    map[string]*template.Template
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
	s := &Server{
		store: cfg.Store, verifier: cfg.Verifier, signer: cfg.Signer, log: cfg.Logger,
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

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"fmtTime": func(t any) string {
			switch v := t.(type) {
			case time.Time:
				if v.IsZero() {
					return "-"
				}
				return v.Local().Format("02/01/2006 15:04:05")
			case *time.Time:
				if v == nil {
					return "-"
				}
				return v.Local().Format("02/01/2006 15:04:05")
			}
			return "-"
		},
		"label": func(v any) string {
			if l, ok := labels[fmt.Sprint(v)]; ok {
				return l
			}
			return fmt.Sprint(v)
		},
		"short": func(s string) string {
			if len(s) > 8 {
				return s[:8]
			}
			return s
		},
	}
	names, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	s.pages = map[string]*template.Template{}
	for _, n := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(n, "templates/"), ".html")
		if base == "layout" {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", n)
		if err != nil {
			return fmt.Errorf("template %s: %w", n, err)
		}
		s.pages[base] = t
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
	mux.Handle("POST /agents/{id}/revoke", s.role(authn.RoleAdmin, s.handleRevoke))
	mux.Handle("POST /agents/{id}/jobs", s.role(authn.RoleOperator, s.handleRunJob))
	mux.Handle("GET /jobs", s.auth(s.handleJobs))
	mux.Handle("GET /jobs/{id}", s.auth(s.handleJob))
	mux.Handle("GET /modules", s.auth(s.handleModules))
	mux.Handle("GET /updates", s.auth(s.handleUpdates))
	mux.Handle("GET /tokens", s.role(authn.RoleAdmin, s.handleTokens))
	mux.Handle("POST /tokens", s.role(authn.RoleAdmin, s.handleCreateToken))
	mux.Handle("GET /audit", s.auth(s.handleAudit))
	mux.Handle("GET /policies", s.auth(s.handlePolicies))
	mux.Handle("GET /policies/new", s.role(authn.RoleAdmin, s.handlePolicyForm))
	mux.Handle("GET /policies/{id}", s.role(authn.RoleAdmin, s.handlePolicyForm))
	mux.Handle("POST /policies", s.role(authn.RoleAdmin, s.handleSavePolicy))
	mux.Handle("POST /policies/{id}/delete", s.role(authn.RoleAdmin, s.handleDeletePolicy))
	return s.secure(mux)
}

// secure sets the security headers on every response.
func (s *Server) secure(next http.Handler) http.Handler {
	csp := "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self' " + s.idpHost +
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
		// Bound request bodies: forms are small, scripts at most 1 MB.
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		// A panic becomes a clean 500 instead of a dropped connection (which
		// clients may silently retry, replaying a one-time step).
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic serving request", "path", r.URL.Path, "panic", v)
				http.Error(w, "errore interno", http.StatusInternalServerError)
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
			http.Error(w, "sessione scaduta", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			if err := s.checkCSRF(r, sess); err != nil {
				http.Error(w, "richiesta non valida", http.StatusForbidden)
				return
			}
		}
		// Refresh the idle timeout.
		if err := s.save(r.Context(), w, sess); err != nil {
			s.fail(w, err)
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
			http.Error(w, "permesso negato", http.StatusForbidden)
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

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "err", err)
	http.Error(w, "errore interno", http.StatusInternalServerError)
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
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	sess := sessionFrom(r.Context())
	p := page{Title: title, Data: data}
	if sess != nil && sess.data.Operator != nil {
		op := sess.data.Operator
		p.Operator, p.CSRF, p.Flash = op, sess.data.CSRF, sess.data.Flash
		p.IsAdmin, p.CanRun = hasRole(op, authn.RoleAdmin), hasRole(op, authn.RoleOperator)
		for _, id := range op.Tenants {
			if t, err := s.store.GetTenant(r.Context(), id); err == nil {
				p.Tenants = append(p.Tenants, t)
				if id == sess.data.Tenant {
					p.Tenant = t
				}
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
	t := s.pages[name]
	if t == nil {
		s.fail(w, fmt.Errorf("no template %s", name))
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
	if sess == nil {
		http.Redirect(w, r, to, http.StatusSeeOther)
		return
	}
	sess.data.Flash = msg
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// labels translates states shown in the UI.
var labels = map[string]string{
	"pending": "in attesa", "active": "attivo", "revoked": "revocato", "online": "online",
	"queued": "in coda", "sent": "inviato", "accepted": "accettato", "running": "in esecuzione",
	"succeeded": "completato", "failed": "fallito", "rejected": "rifiutato", "expired": "scaduto",
	"downloading": "download", "staged": "pronto", "applied": "installato", "rolled_back": "ripristinato",
	"all": "tutti", "clients": "solo client", "servers": "solo server", "client": "client", "server": "server", "unknown": "non noto",
}
