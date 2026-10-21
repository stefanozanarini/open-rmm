package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/jobreq"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/wingetcat"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/policy"
)

// On-demand collections: an operator refreshes what the automatic
// collection gathers (update scan, inventory...) without waiting for the
// next run. They are read-only, so the signer signs them without a new
// sign-in, exactly like the automatic collection (signer.SignCollect).

// latestModule returns the newest published version of a module.
func (s *Server) latestModule(ctx context.Context, id string) (store.Module, bool, error) {
	mods, err := s.store.ListModules(ctx)
	if err != nil {
		return store.Module{}, false, err
	}
	var best store.Module
	found := false
	for _, m := range mods {
		if m.ID == id && (!found || wingetcat.CompareVersions(m.Version, best.Version) > 0) {
			best, found = m, true
		}
	}
	return best, found, nil
}

func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	id := r.PathValue("id")
	if !ok || !ids.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	back := r.PostFormValue("return")
	if !strings.HasPrefix(back, "/agents") {
		back = "/agents/" + id
	}
	module, action := r.PostFormValue("module"), r.PostFormValue("action")
	if !policy.IsCollection(module, action) {
		http.NotFound(w, r)
		return
	}
	a, err := s.store.GetAgent(r.Context(), t, id)
	if err != nil || a.Status != store.AgentActive {
		s.flash(w, r, s.T(r, "Solo gli agenti approvati possono ricevere comandi."), back)
		return
	}
	mod, found, err := s.latestModule(r.Context(), module)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !found {
		s.flash(w, r, s.Tf(r, "Il modulo %s non è pubblicato.", module), back)
		return
	}
	req := &openrmmv1.JobRequest{TenantId: t, AgentId: id, Module: mod.ID, ModuleVersion: mod.Version, ModuleSha256: mod.ManifestSHA256,
		Action: action, ParamsJson: []byte("{}"), TtlSeconds: int64(time.Hour / time.Second), RequestNonce: jobreq.NewRequestNonce()}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := s.signer.SignCollect(ctx, &openrmmv1.SignCollectRequest{Request: req})
	if err != nil {
		s.flash(w, r, s.Tf(r, "Il servizio di firma ha rifiutato il comando: %v", grpcMessage(err)), back)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	for _, sj := range resp.GetJobs() {
		j := store.Job{TenantID: t, ID: sj.GetJobId(), AgentID: sj.GetAgentId(), Module: mod.ID, ModuleVersion: mod.Version,
			Action: action, Params: req.GetParamsJson(), Envelope: sj.GetEnvelope(), CreatedBy: "operator:" + op.Username,
			ExpiresAt: time.Unix(resp.GetExpiresUnix(), 0)}
		if err := s.store.CreateJob(r.Context(), j); err != nil {
			s.fail(w, r, err)
			return
		}
		s.audit(r.Context(), t, op, "job.created", j.ID, map[string]any{"agent": id, "module": mod.ID, "version": mod.Version,
			"action": action, "params": json.RawMessage(j.Params), "approved_by": resp.GetOperator()})
	}
	s.flash(w, r, s.T(r, "Raccolta avviata: i risultati arrivano tra qualche minuto."), back)
}
