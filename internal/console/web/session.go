package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

const (
	// The __Host- prefix makes the browser refuse the cookie unless it is
	// Secure, host-only and scoped to "/".
	cookieName     = "__Host-openrmm"
	idleTimeout    = 30 * time.Minute
	absoluteMaxAge = 8 * time.Hour
	pendingMaxAge  = 10 * time.Minute
)

// Operator is the authenticated operator of a session.
type Operator struct {
	ObjectID string   `json:"oid"`
	TenantID string   `json:"tid"`
	Name     string   `json:"name"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	Tenants  []string `json:"tenants"`
}

// Pending is an authentication round trip in progress.
type Pending struct {
	Purpose      string    `json:"purpose"` // "login", "job" or "policy"
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	StartedAt    time.Time `json:"started_at"`
	// For "job": the serialized JobRequest being approved and where to go.
	JobRequest []byte `json:"job_request,omitempty"`
	Return     string `json:"return,omitempty"`
	// For "policy": the canonical policy document being approved.
	PolicyDoc []byte `json:"policy_doc,omitempty"`
}

// SessionData is stored server-side; the browser only holds a random id.
type SessionData struct {
	Operator  *Operator `json:"operator,omitempty"`
	CSRF      string    `json:"csrf"`
	Theme     string    `json:"theme,omitempty"` // "", light, dark
	Lang      string    `json:"lang,omitempty"`  // "" (from the browser), it, en
	Tenant    string    `json:"tenant,omitempty"`
	Pending   *Pending  `json:"pending,omitempty"`
	Flash     string    `json:"flash,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type session struct {
	id   string
	data SessionData
}

type ctxKey struct{}

func sessionFrom(ctx context.Context) *session {
	s, _ := ctx.Value(ctxKey{}).(*session)
	return s
}

func (s *Server) loadSession(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) < 40 || len(c.Value) > 64 {
		return nil
	}
	ws, err := s.store.GetSession(r.Context(), c.Value, s.now())
	if err != nil {
		return nil
	}
	var d SessionData
	if json.Unmarshal(ws.Data, &d) != nil {
		return nil
	}
	if s.now().Sub(d.CreatedAt) > absoluteMaxAge {
		_ = s.store.DeleteSession(r.Context(), c.Value)
		return nil
	}
	return &session{id: c.Value, data: d}
}

// save writes the session and refreshes its idle expiry.
func (s *Server) save(ctx context.Context, w http.ResponseWriter, sess *session) error {
	raw, err := json.Marshal(sess.data)
	if err != nil {
		return err
	}
	now := s.now()
	exp := now.Add(idleTimeout)
	if hard := sess.data.CreatedAt.Add(absoluteMaxAge); exp.After(hard) {
		exp = hard
	}
	if err := s.store.SaveSession(ctx, store.WebSession{ID: sess.id, Data: raw, LastSeen: now, ExpiresAt: exp}); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: sess.id, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax: the identity provider redirects back with a top-level GET
		MaxAge:   int(absoluteMaxAge / time.Second),
	})
	return nil
}

// newSession creates a fresh session. It is used at login start and again
// after authentication (new id: no session fixation).
func (s *Server) newSession() *session {
	return &session{id: ids.NewSecret(32), data: SessionData{CSRF: ids.NewSecret(32), CreatedAt: s.now()}}
}

func (s *Server) destroy(ctx context.Context, w http.ResponseWriter, sess *session) {
	if sess != nil {
		_ = s.store.DeleteSession(ctx, sess.id)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

var errCSRF = errors.New("invalid CSRF token")

// validCSRF compares a token with the session's.
func validCSRF(sess *session, tok string) bool {
	return tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(sess.data.CSRF)) == 1
}

// checkCSRF validates state-changing requests: the form token must match the
// session, and the Origin header, when sent, must be ours.
func (s *Server) checkCSRF(r *http.Request, sess *session) error {
	if o := r.Header.Get("Origin"); o != "" && o != s.origin {
		return errCSRF
	}
	if r.URL.Path == uploadPath && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		// The upload handler reads the token from the first part, before
		// the file (parsing the form here would buffer the whole upload),
		// and refuses the request without it.
		return nil
	}
	tok := r.PostFormValue("csrf")
	if tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(sess.data.CSRF)) != 1 {
		return errCSRF
	}
	return nil
}
