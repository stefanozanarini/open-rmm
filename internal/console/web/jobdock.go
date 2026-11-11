package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
)

// The job dock: a corner panel on every page with the operator's jobs in
// progress and those just finished, refreshed by app.js from
// /jobs/active.json, so that an operator can go on working after starting
// a job instead of watching its page.

// dockRecent is how long a finished job stays in the panel.
const dockRecent = 10 * time.Minute

type dockJob struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Action   string `json:"action"` // module · action
	State    string `json:"state"`  // for the badge class
	Label    string `json:"label"`  // state in the operator's language
	Progress int    `json:"progress,omitempty"`
	Message  string `json:"message,omitempty"`
	Final    bool   `json:"final"`
}

func (s *Server) handleActiveJobs(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	op := sessionFrom(r.Context()).data.Operator
	if !ok || op == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	jobs, err := s.store.ListJobs(r.Context(), t, "", 200)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	hosts := map[string]string{}
	lang := s.lang(r)
	out := []dockJob{}
	for _, j := range jobs {
		if j.CreatedBy != "operator:"+op.Username {
			continue
		}
		final := j.State.Final()
		if final && (j.FinishedAt == nil || s.now().Sub(*j.FinishedAt) > dockRecent) {
			continue
		}
		host, ok := hosts[j.AgentID]
		if !ok {
			if a, err := s.store.GetAgent(r.Context(), t, j.AgentID); err == nil {
				host = a.Host.Hostname
			}
			hosts[j.AgentID] = host
		}
		d := dockJob{ID: j.ID, Host: host, Action: j.Module + " · " + j.Action, State: string(j.State),
			Label: labelText(lang, string(j.State)), Final: final}
		if !final {
			d.Progress, d.Message = j.Progress, j.Message
		} else if j.State != store.JobSucceeded {
			d.Message = j.Error
		}
		if len(d.Message) > 160 {
			d.Message = d.Message[:157] + "…"
		}
		out = append(out, d)
		if len(out) == 20 {
			break
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// labelText is a value of the labels catalog in lang (the template's
// label function).
func labelText(lang, v string) string {
	if l, ok := labels[v]; ok {
		return tr(lang, l)
	}
	return v
}
