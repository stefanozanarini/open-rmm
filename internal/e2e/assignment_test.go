package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/authn"
	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/workflow"
)

// createTestWorkflow saves a one-step install workflow using the package
// uploaded as sha, and returns its id.
func (e *consoleEnv) createTestWorkflow(t *testing.T, c *http.Client, csrf, sha string) string {
	t.Helper()
	_, _, at := post(t, c, e.console.URL+"/workflows/new", url.Values{"csrf": {csrf}, "name": {"Setup Tool"},
		"s.0.type": {"install"}, "s.0.package": {sha}})
	id := strings.TrimPrefix(at.Path, "/workflows/")
	if id == at.Path || id == "" {
		t.Fatalf("create workflow: %s", at)
	}
	return id
}

func TestPermanentAssignment(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "workflow"))
	c, csrf := e.login(t, admin)

	file := []byte("an installer")
	if code, body := upload(t, c, e.console.URL+"/packages/upload", [][2]string{{"csrf", csrf}, {"name", "Setup Tool"},
		{"version", "2.0"}, {"kind", "msi"}}, file); code != 200 {
		t.Fatalf("upload: %d %s", code, body)
	}
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])
	e.store.SetPackageUnsigned(ctx, e.tenant, sha, true)
	wfID := e.createTestWorkflow(t, c, csrf, sha)

	// A computer group with one approved agent and one still pending.
	approved := e.addWindowsAgent(t, "PC-01")
	pending := ids.NewUUID()
	e.store.CreateAgent(ctx, store.Agent{TenantID: e.tenant, ID: pending, Status: store.AgentPending,
		Host:            store.HostInfo{Hostname: "PC-02", OS: "windows", Arch: "amd64", OSFamily: "client"},
		CertFingerprint: pending, CertNotAfter: time.Now().Add(time.Hour)})
	_, body, at := post(t, c, e.console.URL+"/groups", url.Values{"csrf": {csrf}, "name": {"Ufficio"}, "kind": {"computer"}, "scope": {"public"}})
	groupID := strings.TrimPrefix(at.Path, "/groups/")
	if groupID == at.Path {
		t.Fatalf("create group: %s", body)
	}
	post(t, c, e.console.URL+"/groups/"+groupID, url.Values{"csrf": {csrf}, "do": {"add"}, "names": {"PC-01\nPC-02"}})

	// Only an administrator may create a permanent assignment.
	op := admin
	op.OID, op.Roles = ids.NewUUID(), []string{authn.RoleOperator}
	oc, ocsrf := e.login(t, op)
	if code, _, _ := post(t, oc, e.console.URL+"/workflows/"+wfID+"/assignments",
		url.Values{"csrf": {ocsrf}, "group": {groupID}, "validity_days": {"90"}, "ttl_minutes": {"1440"}}); code != http.StatusForbidden {
		t.Fatalf("operator created an assignment: %d", code)
	}

	e.idp.signIn(admin) // restore the identity after the operator's probe above
	code, body, at := post(t, c, e.console.URL+"/workflows/"+wfID+"/assignments",
		url.Values{"csrf": {csrf}, "group": {groupID}, "validity_days": {"90"}, "ttl_minutes": {"1440"}})
	if code != 200 || at.Path != "/workflows/"+wfID || !strings.Contains(body, "Assegnazione creata") {
		t.Fatalf("create assignment: %d at %s: %s", code, at, body)
	}
	assignments, err := e.store.ListAssignments(ctx, e.tenant)
	if err != nil || len(assignments) != 1 || !assignments[0].Active || assignments[0].Revision != 1 || assignments[0].GroupID != groupID {
		t.Fatalf("assignments = %+v, %v", assignments, err)
	}
	a := assignments[0]
	// The step-up used a fresh sign-in whose nonce named this assignment.
	e.idp.mu.Lock()
	nonce := e.idp.lastAuth.Get("nonce")
	e.idp.mu.Unlock()
	if !strings.HasPrefix(nonce, "assignment.") {
		t.Fatalf("assignment approval nonce = %q", nonce)
	}

	// First tick: dispatches to the approved agent only.
	e.web.RunAssignments(ctx)
	jobs, _ := e.store.ListJobs(ctx, e.tenant, "", 10)
	if len(jobs) != 1 || jobs[0].AgentID != approved || jobs[0].Module != "workflow" || jobs[0].Action != "run" {
		t.Fatalf("jobs after first tick = %+v", jobs)
	}
	var p workflow.Params
	if err := json.Unmarshal(jobs[0].Params, &p); err != nil || p.WorkflowID != wfID || p.Revision != 1 {
		t.Fatalf("job params = %+v, %v", p, err)
	}

	// A second tick, immediately: no duplicate, the run is still in flight.
	e.web.RunAssignments(ctx)
	if jobs, _ = e.store.ListJobs(ctx, e.tenant, "", 10); len(jobs) != 1 {
		t.Fatalf("duplicate dispatch while running: %d jobs", len(jobs))
	}

	// The job finishes long enough ago to be reassessed, and a new
	// computer joins the group: the next tick covers both.
	e.store.UpdateJob(ctx, e.tenant, approved, jobs[0].ID, store.JobUpdate{State: store.JobSucceeded,
		Result: []byte(`{"compliant":false,"verified":true}`)}, time.Now().Add(-25*time.Hour))
	newcomer := e.addWindowsAgent(t, "PC-03")
	post(t, c, e.console.URL+"/groups/"+groupID, url.Values{"csrf": {csrf}, "do": {"add"}, "names": {"PC-03"}})
	e.web.RunAssignments(ctx)
	jobs, _ = e.store.ListJobs(ctx, e.tenant, "", 10)
	targets := map[string]bool{}
	for _, j := range jobs {
		targets[j.AgentID] = true
	}
	if len(jobs) != 3 || !targets[approved] || !targets[newcomer] {
		t.Fatalf("jobs after reassessment = %+v", jobs)
	}

	// Pausing stops new dispatches even though a run would be due.
	for _, j := range jobs {
		e.store.UpdateJob(ctx, e.tenant, j.AgentID, j.ID, store.JobUpdate{State: store.JobSucceeded}, time.Now().Add(-25*time.Hour))
	}
	post(t, c, e.console.URL+"/workflows/"+wfID+"/assignments/"+a.ID, url.Values{"csrf": {csrf}, "do": {"pause"}})
	if got, _ := e.store.GetAssignment(ctx, e.tenant, a.ID); got.Active {
		t.Fatal("assignment still active after pause")
	}
	e.web.RunAssignments(ctx)
	if jobs, _ = e.store.ListJobs(ctx, e.tenant, "", 10); len(jobs) != 3 {
		t.Fatalf("dispatched while paused: %d jobs", len(jobs))
	}

	// Resuming lets it run again.
	post(t, c, e.console.URL+"/workflows/"+wfID+"/assignments/"+a.ID, url.Values{"csrf": {csrf}, "do": {"resume"}})
	e.web.RunAssignments(ctx)
	if jobs, _ = e.store.ListJobs(ctx, e.tenant, "", 10); len(jobs) != 5 {
		t.Fatalf("not resumed: %d jobs", len(jobs))
	}

	// Deleting the group leaves the assignment harmless: nothing to
	// resolve, no panic, no jobs.
	post(t, c, e.console.URL+"/groups/"+groupID, url.Values{"csrf": {csrf}, "do": {"delete"}})
	e.web.RunAssignments(ctx)
	if jobs, _ = e.store.ListJobs(ctx, e.tenant, "", 20); len(jobs) != 5 {
		t.Fatalf("dispatched after the group was deleted: %d jobs", len(jobs))
	}
}

func TestAssignmentSignerIndependentlyChecksExpiry(t *testing.T) {
	e := startConsole(t)
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "workflow"))
	c, csrf := e.login(t, admin)
	file := []byte("installer")
	upload(t, c, e.console.URL+"/packages/upload", [][2]string{{"csrf", csrf}, {"name", "Tool"}, {"version", "1"}, {"kind", "msi"}}, file)
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])
	e.store.SetPackageUnsigned(ctx, e.tenant, sha, true)
	wfID := e.createTestWorkflow(t, c, csrf, sha)
	agent := e.addWindowsAgent(t, "PC-01")
	_, _, at := post(t, c, e.console.URL+"/groups", url.Values{"csrf": {csrf}, "name": {"G"}, "kind": {"computer"}, "scope": {"public"}})
	groupID := strings.TrimPrefix(at.Path, "/groups/")
	post(t, c, e.console.URL+"/groups/"+groupID, url.Values{"csrf": {csrf}, "do": {"add"}, "names": {"PC-01"}})

	// The shortest offered validity is still in the future: create it,
	// then tamper with the stored expiry directly (as if someone edited
	// the database) to prove the SIGNER, not just the console, refuses an
	// expired assignment.
	post(t, c, e.console.URL+"/workflows/"+wfID+"/assignments", url.Values{"csrf": {csrf}, "group": {groupID},
		"validity_days": {"30"}, "ttl_minutes": {"60"}})
	assignments, _ := e.store.ListAssignments(ctx, e.tenant)
	if len(assignments) != 1 {
		t.Fatalf("assignments = %+v", assignments)
	}
	a := assignments[0]
	a.ExpiresAt = time.Now().Add(-time.Hour)
	e.store.CreateAssignment(ctx, a) // memory store: re-create overwrites by id
	_ = agent

	e.web.RunAssignments(ctx)
	if jobs, _ := e.store.ListJobs(ctx, e.tenant, "", 10); len(jobs) != 0 {
		t.Fatalf("signer accepted a stale assignment: %d jobs", len(jobs))
	}
}
