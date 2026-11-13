package web

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/assignreq"
	"github.com/stefanozanarini/tempra-rmm/internal/console/audit"
	"github.com/stefanozanarini/tempra-rmm/internal/console/authn"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/workflow"
)

// Permanent workflow assignments: a workflow revision an administrator
// approves once, with MFA, to run automatically on a group's computers
// (new members included) until it expires or is revoked. The signer
// (internal/console/signer, SignAssignment/SignAssignmentRun) is what
// actually lets this bypass a fresh approval on every run; see its doc
// comment. RunAssignments, called periodically from main, dispatches runs.

// assignmentValidities are the choices for how long an assignment can be
// used before an administrator must approve it again.
var assignmentValidities = []struct {
	Days  int
	Label string
}{{30, "30 giorni"}, {90, "90 giorni"}, {180, "180 giorni"}, {365, "365 giorni"}}

// assignmentReassessInterval: how long a finished run stands before the
// scheduler re-evaluates the computer (catches drift and newly failing
// detection, not only new group members).
const assignmentReassessInterval = 24 * time.Hour

// assignmentRunTTL bounds how long a dispatched job stays valid for an
// offline computer to pick up, capped by the assignment's own max ttl.
const assignmentRunTTL = 24 * time.Hour

// assignmentView is an assignment in the workflow page, with its group's
// name and kind.
type assignmentView struct {
	store.Assignment
	GroupName string
	GroupKind string
}

// buildAssignmentRequest assembles what an administrator approves: the
// workflow's latest revision, pinned module and packages, for a group, with
// the chosen validity and per-run ttl ceiling.
func (s *Server) buildAssignmentRequest(r *http.Request, t, workflowID, groupID string, validityDays, maxTTLMinutes int) (*openrmmv1.AssignmentRequest, string) {
	wf, err := s.store.GetWorkflow(r.Context(), t, workflowID, 0)
	if errors.Is(err, store.ErrNotFound) {
		return nil, s.T(r, "Workflow non trovato.")
	}
	if err != nil {
		return nil, err.Error()
	}
	doc, err := workflow.Parse(wf.Document)
	if err != nil {
		return nil, s.Tf(r, "Workflow non valido: %v", err)
	}
	if _, err := s.findGroup(r, t, groupID); err != nil {
		return nil, s.T(r, "Gruppo non trovato.")
	}
	man, mod, err := s.publishedModule(r.Context(), workflow.ModuleID)
	if err != nil {
		return nil, s.T(r, "Pubblica prima il modulo workflow dalla pagina Moduli.")
	}
	var refs []*openrmmv1.PackageRef
	for _, sha := range doc.Packages() {
		p, err := s.store.GetPackage(r.Context(), t, sha)
		if err != nil {
			return nil, s.T(r, "Un pacchetto del workflow non è più nella libreria.")
		}
		b, _ := hex.DecodeString(p.SHA256)
		refs = append(refs, &openrmmv1.PackageRef{Sha256: b, FileName: p.FileName, Size: p.Size})
		for i := range doc.Steps {
			if doc.Steps[i].Package == sha && p.AllowUnsigned {
				doc.Steps[i].AllowUnsigned = true
			}
		}
	}
	raw, err := json.Marshal(workflow.Params{WorkflowID: wf.ID, Name: wf.Name, Revision: wf.Revision, Workflow: *doc})
	if err != nil {
		return nil, err.Error()
	}
	now := s.now()
	req := &openrmmv1.AssignmentRequest{TenantId: t, WorkflowId: wf.ID, Revision: int32(wf.Revision), // #nosec G115 -- bounded revision counter
		GroupId: groupID, Module: man.ID, ModuleVersion: man.Version, ModuleSha256: mod.ManifestSHA256, Action: workflow.Action,
		ParamsJson: raw, Packages: refs, MaxTtlSeconds: int64(maxTTLMinutes) * 60,
		ExpiresUnix: now.Add(time.Duration(validityDays) * 24 * time.Hour).Unix(), RequestNonce: assignreq.NewRequestNonce()}
	if err := assignreq.Validate(req, now); err != nil {
		return nil, s.Tf(r, "Assegnazione non valida: %v", err)
	}
	return req, ""
}

// handleCreateAssignment starts the MFA approval of a new permanent
// assignment.
func (s *Server) handleCreateAssignment(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	back := "/workflows/" + id
	days, _ := strconv.Atoi(r.PostFormValue("validity_days"))
	valid := false
	for _, v := range assignmentValidities {
		valid = valid || v.Days == days
	}
	if !valid {
		s.flash(w, r, s.T(r, "Scegli per quanto resta valida l'assegnazione."), back)
		return
	}
	ttlMin, err := strconv.Atoi(r.PostFormValue("ttl_minutes"))
	if err != nil || ttlMin < 5 || ttlMin > 48*60 {
		ttlMin = int(assignmentRunTTL / time.Minute)
	}
	req, msg := s.buildAssignmentRequest(r, t, id, r.PostFormValue("group"), days, ttlMin)
	if msg != "" {
		s.flash(w, r, msg, back)
		return
	}
	raw, err := proto.Marshal(req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sess := sessionFrom(r.Context())
	p := &Pending{Purpose: "assignment", State: ids.NewSecret(24), Nonce: assignreq.AuthNonce(req),
		CodeVerifier: oauth2.GenerateVerifier(), StartedAt: s.now(), AssignmentReq: raw, Return: back}
	sess.data.Pending = p
	if err := s.save(r.Context(), w, sess); err != nil {
		s.fail(w, r, err)
		return
	}
	s.redirectStepUp(w, r, sess, p)
}

// completeAssignment finishes the MFA approval and stores the signed
// assignment.
func (s *Server) completeAssignment(w http.ResponseWriter, r *http.Request, sess *session, p *Pending, c *authn.Claims, rawToken string) {
	op, lang := sess.data.Operator, langOf(r, sess)
	if op == nil {
		http.Error(w, tr(lang, "sessione scaduta"), http.StatusUnauthorized)
		return
	}
	if c.ObjectID != op.ObjectID || c.TenantID != op.TenantID {
		http.Error(w, tr(lang, "l'approvazione deve essere fatta dallo stesso operatore"), http.StatusForbidden)
		return
	}
	req := &openrmmv1.AssignmentRequest{}
	if err := proto.Unmarshal(p.AssignmentReq, req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !assignreq.CheckAuthNonce(c.Nonce, req) {
		http.Error(w, tr(lang, "approvazione non valida per questa assegnazione"), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := s.signer.SignAssignment(ctx, &openrmmv1.SignAssignmentRequest{Request: req, IdToken: rawToken})
	if err != nil {
		s.audit(r.Context(), req.GetTenantId(), op, "assignment.refused", req.GetWorkflowId(), map[string]any{"reason": err.Error()})
		s.flashTo(w, r, sess, trf(lang, "Il servizio di firma ha rifiutato l'assegnazione: %v", err), p.Return)
		return
	}
	a := store.Assignment{TenantID: req.GetTenantId(), ID: ids.NewUUID(), WorkflowID: req.GetWorkflowId(),
		Revision: int(req.GetRevision()), GroupID: req.GetGroupId(), Envelope: resp.GetEnvelope(),
		MaxTTLSeconds: int(req.GetMaxTtlSeconds()), ExpiresAt: time.Unix(req.GetExpiresUnix(), 0), CreatedBy: "operator:" + op.Username}
	if err := s.store.CreateAssignment(r.Context(), a); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r.Context(), req.GetTenantId(), op, "assignment.created", a.ID, map[string]any{
		"workflow": req.GetWorkflowId(), "revision": req.GetRevision(), "group": req.GetGroupId(),
		"expires_at": a.ExpiresAt, "approved_by": resp.GetOperator()})
	s.flashTo(w, r, sess, trf(lang, "Assegnazione creata: valida fino al %s.", a.ExpiresAt.Format(dateFormat(lang))), p.Return)
}

// handleSetAssignmentActive pauses or resumes an assignment, without a new
// approval: it only controls whether the scheduler uses the already-signed,
// not yet expired assignment, never its content.
func (s *Server) handleSetAssignmentActive(w http.ResponseWriter, r *http.Request) {
	t, ok := tenantOf(r)
	if !ok {
		http.Error(w, s.T(r, "nessun tenant"), http.StatusForbidden)
		return
	}
	wfID, id := r.PathValue("id"), r.PathValue("aid")
	back := "/workflows/" + wfID
	a, err := s.store.GetAssignment(r.Context(), t, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && a.WorkflowID != wfID) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	op := sessionFrom(r.Context()).data.Operator
	active := r.PostFormValue("do") == "resume"
	if active && s.now().After(a.ExpiresAt) {
		s.flash(w, r, s.T(r, "L'assegnazione è scaduta: creane una nuova."), back)
		return
	}
	if err := s.store.SetAssignmentActive(r.Context(), t, id, active, "operator:"+op.Username, s.now()); err != nil {
		s.fail(w, r, err)
		return
	}
	action, msg := "assignment.paused", s.T(r, "Assegnazione sospesa.")
	if active {
		action, msg = "assignment.resumed", s.T(r, "Assegnazione ripresa.")
	}
	s.audit(r.Context(), t, op, action, id, nil)
	s.flash(w, r, msg, back)
}

// assignmentsFor returns the assignments of a workflow, with their group's
// name, newest first.
func (s *Server) assignmentsFor(r *http.Request, t, workflowID string) ([]assignmentView, error) {
	all, err := s.store.ListAssignments(r.Context(), t)
	if err != nil {
		return nil, err
	}
	groups, err := s.visibleGroups(r, t)
	if err != nil {
		return nil, err
	}
	names := map[string]store.Group{}
	for _, g := range groups {
		names[g.ID] = g
	}
	var out []assignmentView
	for _, a := range all {
		if a.WorkflowID != workflowID {
			continue
		}
		g := names[a.GroupID]
		out = append(out, assignmentView{Assignment: a, GroupName: g.Name, GroupKind: g.Kind})
	}
	return out, nil
}

// RunAssignments dispatches runs of every active, unexpired assignment on
// the computers of its group that are due: never run yet, or whose last
// run finished at least assignmentReassessInterval ago. A run still in
// flight is left alone.
func (s *Server) RunAssignments(ctx context.Context) {
	if s.signer == nil {
		return
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		s.log.Error("workflow assignments", "err", err)
		return
	}
	now := s.now()
	for _, t := range tenants {
		assignments, err := s.store.ListAssignments(ctx, t.ID)
		if err != nil {
			s.log.Error("workflow assignments", "tenant", t.ID, "err", err)
			continue
		}
		var due []store.Assignment
		for _, a := range assignments {
			if a.Active && now.Before(a.ExpiresAt) {
				due = append(due, a)
			}
		}
		if len(due) == 0 {
			continue
		}
		agents, err := s.tenantAgents(ctx, t.ID)
		if err != nil {
			s.log.Error("workflow assignments", "tenant", t.ID, "err", err)
			continue
		}
		runs, err := s.workflowRuns(ctx, t.ID)
		if err != nil {
			s.log.Error("workflow assignments", "tenant", t.ID, "err", err)
			continue
		}
		for _, a := range due {
			s.runAssignment(ctx, a, agents, runs[a.WorkflowID], now)
		}
	}
}

// runAssignment issues a run for the agents of a's group that are due.
func (s *Server) runAssignment(ctx context.Context, a store.Assignment, agents []groupAgent, runs []wfRun, now time.Time) {
	g, err := s.store.ListGroups(ctx, a.TenantID)
	if err != nil {
		return
	}
	var group *store.Group
	for i := range g {
		if g[i].ID == a.GroupID {
			group = &g[i]
			break
		}
	}
	if group == nil {
		return // the group was deleted; nothing to do until the admin revokes
	}
	last := map[string]wfRun{}
	for _, run := range runs {
		last[run.AgentID] = run
	}
	var targets []string
	for _, ag := range activeIDs(groupAgents(*group, agents)) {
		r, ran := last[ag]
		switch {
		case !ran:
		case r.Job.FinishedAt == nil: // still queued, sent, accepted or running
			continue
		case now.Sub(*r.Job.FinishedAt) < assignmentReassessInterval:
			continue
		}
		targets = append(targets, ag)
		if len(targets) >= assignreq.MaxAgents {
			break
		}
	}
	if len(targets) == 0 {
		return
	}
	// Decode the console's own copy of what was approved, to carry its
	// parameters into the job records (workflowRuns reads them to tell
	// which workflow and revision a job belongs to); this is bookkeeping
	// only, not a trust decision — the signer independently re-verifies
	// the envelope's signature before issuing anything.
	env := &openrmmv1.SignedEnvelope{}
	req := &openrmmv1.AssignmentRequest{}
	if err := proto.Unmarshal(a.Envelope, env); err != nil {
		s.log.Error("workflow assignment envelope", "assignment", a.ID, "err", err)
		return
	}
	if err := proto.Unmarshal(env.GetPayload(), req); err != nil {
		s.log.Error("workflow assignment payload", "assignment", a.ID, "err", err)
		return
	}
	ttl := assignmentRunTTL
	if max := time.Duration(a.MaxTTLSeconds) * time.Second; max < ttl {
		ttl = max
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := s.signer.SignAssignmentRun(ctx, &openrmmv1.SignAssignmentRunRequest{
		AssignmentEnvelope: a.Envelope, AgentIds: targets, TtlSeconds: int64(ttl / time.Second)})
	if err != nil {
		s.log.Warn("workflow assignment run refused", "assignment", a.ID, "err", err)
		return
	}
	for _, sj := range resp.GetJobs() {
		j := store.Job{TenantID: a.TenantID, ID: sj.GetJobId(), AgentID: sj.GetAgentId(), Module: req.GetModule(),
			ModuleVersion: req.GetModuleVersion(), Action: req.GetAction(), Params: req.GetParamsJson(), Envelope: sj.GetEnvelope(),
			CreatedBy: "automatic (assignment)", ExpiresAt: time.Unix(resp.GetExpiresUnix(), 0)}
		if err := s.store.CreateJob(ctx, j); err != nil {
			s.log.Error("workflow assignment job", "assignment", a.ID, "agent", sj.GetAgentId(), "err", err)
			continue
		}
		details := map[string]any{"agent": j.AgentID, "module": j.Module, "action": j.Action,
			"approved_by": resp.GetOperator(), "assignment": a.ID}
		if _, err := s.store.AppendAudit(ctx, audit.Event{TenantID: a.TenantID, Actor: "console", Action: "job.created",
			Target: j.ID, OccurredAt: s.now(), Details: details}); err != nil {
			s.log.Error("audit append failed", "err", err)
		}
	}
}
