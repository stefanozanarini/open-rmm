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

	"golang.org/x/net/websocket"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/modules"
	"github.com/stefanozanarini/tempra-rmm/internal/screensession"
)

// Remote-control sessions: one MFA approval opens a view of one agent's
// screen, with mouse/keyboard control, for a limited time. Served the
// same way as the interactive shell (same Shell stream, same gateway),
// but the module requires a logged-on, unlocked Windows user session
// (internal/agent/usersession): the agent runs as LocalSystem and has no
// desktop of its own.

const (
	screenModule = "screen"
	// screenPickup is how long the agent has to start an approved session.
	screenPickup = 10 * time.Minute
	maxScreenMsg = 256 << 10
)

// isScreenModule tells whether a module version opens remote-control
// sessions.
func (s *Server) isScreenModule(ctx context.Context, id, version string) bool {
	m, err := s.store.GetModule(ctx, id, version)
	if err != nil {
		return false
	}
	man, err := modules.ParseManifest(m.Manifest)
	return err == nil && man.HasCapability(modules.CapScreenSession)
}

// screenModuleFor returns the newest screen module for the agent's platform.
func (s *Server) screenModuleFor(r *http.Request, a store.Agent) (store.Module, bool) {
	latest, err := s.latestModules(r)
	if err != nil {
		return store.Module{}, false
	}
	m, err := s.store.GetModule(r.Context(), screenModule, latest[screenModule])
	if err != nil {
		return store.Module{}, false
	}
	man, err := modules.ParseManifest(m.Manifest)
	if err != nil || !man.HasCapability(modules.CapScreenSession) {
		return store.Module{}, false
	}
	if _, ok := man.Entrypoints[a.Host.OS+"/"+a.Host.Arch]; !ok {
		return store.Module{}, false
	}
	return m, true
}

func (s *Server) handleOpenScreen(w http.ResponseWriter, r *http.Request) {
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
	mod, ok := s.screenModuleFor(r, a)
	if !ok || s.shell == nil {
		s.flash(w, r, s.T(r, "Il controllo remoto non è disponibile su questa console."), back)
		return
	}
	minutes, err := strconv.Atoi(r.PostFormValue("minutes"))
	if err != nil || minutes < 5 || minutes > 60 {
		minutes = 30
	}
	params, _ := json.Marshal(map[string]int{"minutes": minutes})
	req := &openrmmv1.JobRequest{TenantId: t, AgentId: id, Module: mod.ID, ModuleVersion: mod.Version, ModuleSha256: mod.ManifestSHA256,
		Action: "open", ParamsJson: params, TtlSeconds: int64(screenPickup / time.Second), RequestNonce: jobreq.NewRequestNonce()}
	if err := jobreq.Validate(req); err != nil {
		s.flash(w, r, s.Tf(r, "Richiesta non valida: %v", err), back)
		return
	}
	s.startStepUp(w, r, sessionFrom(r.Context()), req, back)
}

// screenJob returns a screen job that the operator approved and may attach to.
func (s *Server) screenJob(r *http.Request) (store.Job, store.Agent, bool) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		return store.Job{}, store.Agent{}, false
	}
	j, err := s.store.GetJob(r.Context(), t, id)
	op := sessionFrom(r.Context()).data.Operator
	// Only the operator who approved the session may use it.
	if err != nil || j.CreatedBy != "operator:"+op.Username || !s.isScreenModule(r.Context(), j.Module, j.ModuleVersion) {
		return store.Job{}, store.Agent{}, false
	}
	a, err := s.store.GetAgent(r.Context(), t, j.AgentID)
	if err != nil {
		return store.Job{}, store.Agent{}, false
	}
	return j, a, true
}

type screenData struct {
	Job     store.Job
	Agent   store.Agent
	Minutes int
	By      string // approving operator
}

func (s *Server) handleScreenPage(w http.ResponseWriter, r *http.Request) {
	j, a, ok := s.screenJob(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// This page draws to a <canvas> with its own small script, served by
	// the console: no third-party script or style.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
		"connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	var p struct {
		Minutes int `json:"minutes"`
	}
	_ = json.Unmarshal(j.Params, &p)
	s.render(w, r, "screen", s.Tf(r, "Controllo remoto di %s", a.Host.Hostname), screenData{Job: j, Agent: a, Minutes: p.Minutes,
		By: strings.TrimPrefix(j.CreatedBy, "operator:")})
}

// screenMsg is the browser's input events; the server turns them into the
// internal/screensession wire format the agent's screenhelper speaks.
type screenMsg struct {
	T      string `json:"t"` // move, button, wheel, key, close
	X      int32  `json:"x,omitempty"`
	Y      int32  `json:"y,omitempty"`
	Button byte   `json:"button,omitempty"`
	Down   bool   `json:"down,omitempty"`
	Delta  int32  `json:"delta,omitempty"`
	Key    uint32 `json:"key,omitempty"`
}

// handleScreenSocket joins the browser's canvas to the session.
func (s *Server) handleScreenSocket(w http.ResponseWriter, r *http.Request) {
	j, a, ok := s.screenJob(r)
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
		Handler: func(ws *websocket.Conn) { s.serveScreen(ws, r, j, a, op) },
	}
	srv.ServeHTTP(w, r)
}

func (s *Server) serveScreen(ws *websocket.Conn, r *http.Request, j store.Job, a store.Agent, op *Operator) {
	defer ws.Close()
	// The server's write timeout does not apply to a session.
	_ = ws.SetDeadline(time.Time{})
	ws.MaxPayloadBytes = maxScreenMsg
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
	s.audit(r.Context(), j.TenantID, op, "screen.attached", j.ID, map[string]any{"agent": a.ID, "hostname": a.Host.Hostname})
	var wsMu sync.Mutex
	sendWS := func(v any) error {
		wsMu.Lock()
		defer wsMu.Unlock()
		return websocket.Message.Send(ws, v)
	}
	// Input events to the agent.
	go func() {
		defer cancel()
		for {
			var raw string
			if err := websocket.Message.Receive(ws, &raw); err != nil {
				return
			}
			var m screenMsg
			if json.Unmarshal([]byte(raw), &m) != nil {
				continue
			}
			f := &openrmmv1.ShellFrame{}
			switch m.T {
			case "move":
				f.Data = screensession.EncodeMove(m.X, m.Y)
			case "button":
				f.Data = screensession.EncodeButton(m.Button, m.Down)
			case "wheel":
				f.Data = screensession.EncodeWheel(m.Delta)
			case "key":
				f.Data = screensession.EncodeKey(m.Key, m.Down)
			case "close":
				f.Close = true
			default:
				continue
			}
			if stream.Send(f) != nil || f.Close {
				return
			}
		}
	}()
	// A session the agent refuses (local policy, no logged-on user,
	// offline) never sends data: watch the job and say why instead of
	// showing a blank screen.
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
	// Screen frames to the browser: forwarded as opaque bytes, exactly as
	// the agent sent them. Only the two real endpoints (screenhelper and
	// the browser's own script) parse internal/screensession's framing.
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
	s.audit(context.WithoutCancel(r.Context()), j.TenantID, op, "screen.detached", j.ID, map[string]any{"agent": a.ID})
}
