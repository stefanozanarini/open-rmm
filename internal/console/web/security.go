package web

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/stefanozanarini/open-rmm/internal/accesslog"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// alertView is an alert with its agent's hostname.
type alertView struct {
	store.Alert
	Hostname string
}

type alertsData struct {
	All    bool
	Alerts []alertView
}

func (s *Server) alertViews(r *http.Request, tenant string, alerts []store.Alert) []alertView {
	names := map[string]string{}
	if agents, err := s.store.ListAgents(r.Context(), tenant); err == nil {
		for _, a := range agents {
			names[a.ID] = a.Host.Hostname
		}
	}
	out := make([]alertView, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, alertView{Alert: a, Hostname: names[a.AgentID]})
	}
	return out
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	d := alertsData{All: r.URL.Query().Get("all") == "1"}
	alerts, err := s.store.ListAlerts(r.Context(), t, "", !d.All, 500)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !d.All {
		// Open alerts: the most severe first, then the most recent.
		rank := map[string]int{store.SeverityCritical: 0, store.SeverityWarning: 1, store.SeverityInfo: 2}
		sort.SliceStable(alerts, func(i, j int) bool { return rank[alerts[i].Severity] < rank[alerts[j].Severity] })
	}
	d.Alerts = s.alertViews(r, t, alerts)
	s.render(w, r, "alerts", "Avvisi", d)
}

func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	back := "/alerts"
	if ret := r.PostFormValue("return"); strings.HasPrefix(ret, "/agents/") && ids.IsUUID(strings.TrimPrefix(ret, "/agents/")) {
		back = ret
	}
	switch err := s.store.AcknowledgeAlert(r.Context(), t, id, "operator:"+op.Username, s.now()); {
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), t, op, "alert.acknowledged", id, nil)
	s.flash(w, r, "Avviso preso in carico.", back)
}

type settingsData struct {
	Subnets  string
	Defaults []string
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	cur, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := settingsData{Subnets: strings.Join(cur.RDPAllowedSubnets, "\n")}
	for _, p := range accesslog.DefaultAllowed {
		d.Defaults = append(d.Defaults, p.String())
	}
	s.render(w, r, "settings", "Impostazioni", d)
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, "nessun tenant", http.StatusForbidden)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	cur, err := s.store.GetSettings(r.Context(), t)
	if err != nil {
		s.fail(w, err)
		return
	}
	lines := strings.FieldsFunc(r.PostFormValue("rdp_subnets"), func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' })
	prefixes, err := accesslog.ParseSubnets(lines)
	if err != nil {
		s.flash(w, r, "Subnet non valida: "+err.Error(), "/settings")
		return
	}
	if len(prefixes) > 200 {
		s.flash(w, r, "Al massimo 200 subnet.", "/settings")
		return
	}
	next := cur
	next.RDPAllowedSubnets = nil
	for _, p := range prefixes {
		next.RDPAllowedSubnets = append(next.RDPAllowedSubnets, p.String())
	}
	if err := s.store.PutSettings(r.Context(), t, next, "operator:"+op.Username); err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), t, op, "settings.updated", t, map[string]any{
		"rdp_allowed_subnets": next.RDPAllowedSubnets, "previous": cur.RDPAllowedSubnets})
	s.flash(w, r, "Impostazioni salvate.", "/settings")
}
