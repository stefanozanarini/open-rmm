package web

import (
	"context"
	"net/http"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
)

// watchSession follows the job behind an interactive session (shell or
// remote control) and tells the browser where it stands, through send: the
// browser's own connection to the console says nothing about the agent,
// so until the agent joins it would otherwise show an empty terminal or a
// black screen. It says whether the agent is still to pick the job up
// (and, if it is not even connected, until when it may), is starting the
// session or has joined; when the agent refuses the session or never
// collects it, it says why and calls cancel.
func (s *Server) watchSession(ctx context.Context, r *http.Request, j store.Job, send func(any) error, cancel context.CancelFunc) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	last := ""
	for {
		msg := ""
		if cur, err := s.store.GetJob(ctx, j.TenantID, j.ID); err == nil {
			switch cur.State {
			case store.JobQueued:
				msg = s.T(r, "In attesa che l'agente riceva la richiesta…")
				if a, err := s.store.GetAgent(ctx, j.TenantID, j.AgentID); err == nil && !s.online(a) {
					timeFmt := dateFormat(s.lang(r)) + " 15:04"
					seen := "-"
					if a.LastSeenAt != nil {
						seen = a.LastSeenAt.Local().Format(timeFmt)
					}
					msg = s.Tf(r, "L'agente non è collegato (ultimo contatto %s): la sessione partirà se si ricollega entro le %s.",
						seen, cur.ExpiresAt.Local().Format("15:04"))
				}
			case store.JobSent, store.JobAccepted:
				msg = s.T(r, "L'agente sta avviando la sessione…")
			case store.JobRunning:
				msg = s.T(r, "Connesso")
			case store.JobSucceeded:
			case store.JobExpired:
				_ = send(s.T(r, "Sessione scaduta: l'agente non si è collegato in tempo."))
				cancel()
				return
			default:
				_ = send(s.Tf(r, "Sessione rifiutata dall'agente: %s", cur.Error))
				cancel()
				return
			}
		}
		if msg != "" && msg != last {
			if send(msg) != nil {
				return
			}
			last = msg
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
