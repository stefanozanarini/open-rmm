package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/websocket"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
)

// Interactive shells: one MFA approval opens a session on one agent for a
// limited time; the agent allows it only when its local policy does. Every
// line typed is recorded in the audit log.

const (
	shellModule = "shell"
	// shellPickup is how long the agent has to start an approved session.
	shellPickup  = 10 * time.Minute
	maxShellMsg  = 64 << 10
	maxAuditLine = 2000
)

// isShellModule tells whether a module version opens interactive shells.
func (s *Server) isShellModule(ctx context.Context, id, version string) bool {
	m, err := s.store.GetModule(ctx, id, version)
	if err != nil {
		return false
	}
	man, err := modules.ParseManifest(m.Manifest)
	return err == nil && man.HasCapability(modules.CapInteractiveShell)
}

// shellModuleFor returns the newest shell module for the agent's platform.
func (s *Server) shellModuleFor(r *http.Request, a store.Agent) (store.Module, bool) {
	latest, err := s.latestModules(r)
	if err != nil {
		return store.Module{}, false
	}
	m, err := s.store.GetModule(r.Context(), shellModule, latest[shellModule])
	if err != nil {
		return store.Module{}, false
	}
	man, err := modules.ParseManifest(m.Manifest)
	if err != nil || !man.HasCapability(modules.CapInteractiveShell) {
		return store.Module{}, false
	}
	if _, ok := man.Entrypoints[a.Host.OS+"/"+a.Host.Arch]; !ok {
		return store.Module{}, false
	}
	return m, true
}

func (s *Server) handleOpenShell(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	back := "/agents/" + id
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil || a.Status != store.AgentActive {
		s.flash(w, r, s.T(r, "Solo gli agenti approvati possono ricevere comandi."), back)
		return
	}
	mod, ok := s.shellModuleFor(r, a)
	if !ok || s.shell == nil {
		s.flash(w, r, s.T(r, "La shell interattiva non è disponibile su questa console."), back)
		return
	}
	minutes, err := strconv.Atoi(r.PostFormValue("minutes"))
	if err != nil || minutes < 5 || minutes > 60 {
		minutes = 30
	}
	params, _ := json.Marshal(map[string]int{"minutes": minutes})
	req := &openrmmv1.JobRequest{TenantId: t, AgentId: id, Module: mod.ID, ModuleVersion: mod.Version, ModuleSha256: mod.ManifestSHA256,
		Action: "open", ParamsJson: params, TtlSeconds: int64(shellPickup / time.Second), RequestNonce: jobreq.NewRequestNonce()}
	if err := jobreq.Validate(req); err != nil {
		s.flash(w, r, s.Tf(r, "Richiesta non valida: %v", err), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}

// shellJob returns a shell job that the operator approved and may attach to.
func (s *Server) shellJob(r *http.Request) (store.Job, store.Agent, bool) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		return store.Job{}, store.Agent{}, false
	}
	j, err := s.store.GetJob(r.Context(), t, id)
	op := sessionFrom(r.Context()).data.Operator
	// Only the operator who approved the session may use it.
	if err != nil || j.CreatedBy != "operator:"+op.Username || !s.isShellModule(r.Context(), j.Module, j.ModuleVersion) {
		return store.Job{}, store.Agent{}, false
	}
	a, err := s.store.GetAgent(r.Context(), t, j.AgentID)
	if err != nil {
		return store.Job{}, store.Agent{}, false
	}
	return j, a, true
}

type shellData struct {
	Job     store.Job
	Agent   store.Agent
	Minutes int
	By      string // approving operator
}

func (s *Server) handleShellPage(w http.ResponseWriter, r *http.Request) {
	j, a, ok := s.shellJob(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// This page alone runs scripts: xterm.js and its loader, served by the
	// console; xterm.js adds its own style elements.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
		"connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	var p struct {
		Minutes int `json:"minutes"`
	}
	_ = json.Unmarshal(j.Params, &p)
	s.render(w, r, "shell", s.Tf(r, "Shell su %s", a.Host.Hostname), shellData{Job: j, Agent: a, Minutes: p.Minutes,
		By: strings.TrimPrefix(j.CreatedBy, "operator:")})
}

type shellMsg struct {
	T string `json:"t"` // i: input, r: resize, c: close
	D string `json:"d,omitempty"`
	C uint32 `json:"c,omitempty"`
	R uint32 `json:"r,omitempty"`
}

// handleShellSocket joins the browser's terminal to the session.
func (s *Server) handleShellSocket(w http.ResponseWriter, r *http.Request) {
	j, a, ok := s.shellJob(r)
	if !ok || s.shell == nil {
		http.NotFound(w, r)
		return
	}
	sess := sessionFrom(r.Context())
	op := sess.data.Operator
	srv := websocket.Server{
		Handshake: func(_ *websocket.Config, req *http.Request) error {
			// Same-origin only; over a federation link the central console
			// has checked the origin.
			if op.Federated || req.Header.Get("Origin") == s.origin {
				return nil
			}
			return errors.New("origin not allowed")
		},
		Handler: func(ws *websocket.Conn) { s.serveShell(ws, r, j, a, op) },
	}
	srv.ServeHTTP(w, r)
}

func (s *Server) serveShell(ws *websocket.Conn, r *http.Request, j store.Job, a store.Agent, op *Operator) {
	defer ws.Close()
	// The server's write timeout does not apply to a session.
	_ = ws.SetDeadline(time.Time{})
	ws.MaxPayloadBytes = maxShellMsg
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stream, err := s.shell.Attach(ctx)
	if err == nil {
		err = stream.Send(&openrmmv1.ShellFrame{TenantId: j.TenantID, JobId: j.ID})
	}
	if err != nil {
		_ = websocket.Message.Send(ws, s.T(r, "La sessione non è disponibile."))
		return
	}
	s.audit(r.Context(), j.TenantID, op, "shell.attached", j.ID, map[string]any{"agent": a.ID, "hostname": a.Host.Hostname})
	rec := &lineRecorder{flush: func(line string) {
		s.audit(context.WithoutCancel(r.Context()), j.TenantID, op, "shell.input", j.ID, map[string]any{"agent": a.ID, "line": line})
	}}
	defer rec.close()
	var wsMu sync.Mutex
	sendWS := func(v any) error {
		wsMu.Lock()
		defer wsMu.Unlock()
		return websocket.Message.Send(ws, v)
	}
	// Terminal to the agent.
	go func() {
		defer cancel()
		for {
			var raw string
			if err := websocket.Message.Receive(ws, &raw); err != nil {
				return
			}
			var m shellMsg
			if json.Unmarshal([]byte(raw), &m) != nil {
				continue
			}
			f := &openrmmv1.ShellFrame{}
			switch m.T {
			case "i":
				rec.write(m.D)
				f.Data = []byte(m.D)
			case "r":
				f.Cols, f.Rows = min(m.C, 1000), min(m.R, 1000)
			case "c":
				f.Close = true
			default:
				continue
			}
			if stream.Send(f) != nil || f.Close {
				return
			}
		}
	}()
	// A session the agent refuses (local policy, offline) never sends data:
	// watch the job and say why instead of showing an empty terminal.
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			cur, err := s.store.GetJob(ctx, j.TenantID, j.ID)
			if err != nil || !cur.State.Final() || cur.State == store.JobSucceeded {
				continue
			}
			msg := s.Tf(r, "Sessione rifiutata dall'agente: %s", cur.Error)
			if cur.State == store.JobExpired {
				msg = s.T(r, "Sessione scaduta: l'agente non si è collegato in tempo.")
			}
			_ = sendWS(msg)
			cancel()
			return
		}
	}()
	// Agent to the terminal.
	for {
		f, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				_ = sendWS(s.T(r, "La sessione non è disponibile."))
			}
			break
		}
		if len(f.GetData()) > 0 {
			if sendWS(f.GetData()) != nil {
				break
			}
		}
		if f.GetClose() {
			_ = sendWS(s.T(r, "Sessione chiusa."))
			break
		}
	}
	_ = stream.CloseSend()
	s.audit(context.WithoutCancel(r.Context()), j.TenantID, op, "shell.detached", j.ID, map[string]any{"agent": a.ID})
}

// lineRecorder turns keystrokes into the lines typed, for the audit log:
// backspace edits the line, escape sequences (arrows…) are dropped, other
// control characters are shown as ^X.
type lineRecorder struct {
	mu    sync.Mutex
	line  []rune
	esc   int // 0 none, 1 after ESC, 2 inside CSI
	flush func(string)
}

func (l *lineRecorder) write(s string) {
	l.mu.Lock()
	var done []string
	for _, c := range s {
		switch {
		case l.esc == 1:
			l.esc = 0
			if c == '[' || c == 'O' {
				l.esc = 2
			}
		case l.esc == 2:
			if c >= 0x40 && c <= 0x7e {
				l.esc = 0
			}
		case c == 0x1b:
			l.esc = 1
		case c == '\r' || c == '\n':
			done = append(done, string(l.line))
			l.line = l.line[:0]
		case c == 0x7f || c == '\b':
			if len(l.line) > 0 {
				l.line = l.line[:len(l.line)-1]
			}
		case c == 0x03:
			done = append(done, string(l.line)+"^C")
			l.line = l.line[:0]
		case unicode.IsControl(c):
			if c < 0x20 {
				l.line = append(l.line, '^', rune('@'+c))
			}
		case len(l.line) < maxAuditLine:
			l.line = append(l.line, c)
		}
	}
	l.mu.Unlock()
	for _, d := range done {
		if strings.TrimSpace(d) != "" {
			l.flush(d)
		}
	}
}

func (l *lineRecorder) close() {
	l.mu.Lock()
	rest := string(l.line)
	l.line = nil
	l.mu.Unlock()
	if strings.TrimSpace(rest) != "" {
		l.flush(rest + " (not sent)")
	}
}
