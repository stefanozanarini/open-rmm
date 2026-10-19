package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

func TestAuditChain(t *testing.T) {
	testAuditChain(t, NewMemory())
}

// testAuditChain is shared with the PostgreSQL integration test.
func testAuditChain(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := Tenant{ID: ids.NewUUID(), Name: "t"}
	if err := s.CreateTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err := s.AppendAudit(ctx, audit.Event{TenantID: tenant.ID, Actor: "test", Action: "x",
			OccurredAt: time.Now(), Details: map[string]any{"i": i, "nested": map[string]any{"b": 2, "a": "1"}}}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.ListAudit(ctx, tenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("got %d events", len(events))
	}
	if err := audit.VerifyChain(events); err != nil {
		t.Fatal(err)
	}
	events[2].Actor = "someone else"
	if err := audit.VerifyChain(events); err == nil {
		t.Fatal("tampering not detected")
	}
}

func TestEnrollmentTokenLimits(t *testing.T) {
	testEnrollmentTokenLimits(t, NewMemory())
}

func testEnrollmentTokenLimits(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := Tenant{ID: ids.NewUUID(), Name: "t"}
	if err := s.CreateTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mk := func(maxUses int, exp time.Time) string {
		secret := ids.NewSecret(32)
		if err := s.CreateEnrollmentToken(ctx, EnrollmentToken{ID: ids.NewUUID(), TenantID: tenant.ID,
			MaxUses: maxUses, ExpiresAt: exp}, HashToken(secret)); err != nil {
			t.Fatal(err)
		}
		return secret
	}
	twice := mk(2, now.Add(time.Hour))
	for i := range 2 {
		if _, err := s.ConsumeEnrollmentToken(ctx, HashToken(twice), now); err != nil {
			t.Fatalf("use %d: %v", i+1, err)
		}
	}
	if _, err := s.ConsumeEnrollmentToken(ctx, HashToken(twice), now); err != ErrTokenInvalid {
		t.Fatalf("third use: %v", err)
	}
	expired := mk(5, now.Add(-time.Second))
	if _, err := s.ConsumeEnrollmentToken(ctx, HashToken(expired), now); err != ErrTokenInvalid {
		t.Fatalf("expired token: %v", err)
	}
	if _, err := s.ConsumeEnrollmentToken(ctx, HashToken("never issued"), now); err != ErrTokenInvalid {
		t.Fatalf("unknown token: %v", err)
	}
}

func TestApprovalAndRotation(t *testing.T) { testApprovalAndRotation(t, NewMemory()) }

func testApprovalAndRotation(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := Tenant{ID: ids.NewUUID(), Name: "t"}
	if err := s.CreateTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	a := Agent{TenantID: tenant.ID, ID: ids.NewUUID(), Status: AgentPending, Host: HostInfo{Hostname: "pc"},
		CertFingerprint: "fp1", CertNotAfter: time.Now().Add(time.Hour)}
	if err := s.CreateAgent(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveAgent(ctx, tenant.ID, a.ID, "op", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveAgent(ctx, tenant.ID, a.ID, "op", time.Now()); err != ErrNotPending {
		t.Fatalf("second approval: %v", err)
	}
	if err := s.ApproveAgent(ctx, tenant.ID, ids.NewUUID(), "op", time.Now()); err != ErrNotFound {
		t.Fatalf("unknown agent: %v", err)
	}
	got, _ := s.GetAgent(ctx, tenant.ID, a.ID)
	if got.Status != AgentActive || got.ApprovedBy != "op" || got.ApprovedAt == nil {
		t.Fatalf("approved agent = %+v", got)
	}

	exp := time.Now().Add(90 * 24 * time.Hour)
	if err := s.RotateAgentCert(ctx, tenant.ID, a.ID, "fp1", "fp2", exp); err != nil {
		t.Fatal(err)
	}
	// Renewing again with the previous certificate (lost response) works.
	if err := s.RotateAgentCert(ctx, tenant.ID, a.ID, "fp1", "fp3", exp); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAgent(ctx, tenant.ID, a.ID)
	if got.CertFingerprint != "fp3" || got.PrevCertFingerprint != "fp1" {
		t.Fatalf("after rotations: current %s prev %s", got.CertFingerprint, got.PrevCertFingerprint)
	}
	if err := s.RotateAgentCert(ctx, tenant.ID, a.ID, "fp2", "fp4", exp); err != ErrCertMismatch {
		t.Fatalf("rotation with a superseded certificate: %v", err)
	}
	if err := s.ForgetPrevCert(ctx, tenant.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateAgentCert(ctx, tenant.ID, a.ID, "fp1", "fp5", exp); err != ErrCertMismatch {
		t.Fatalf("rotation with a forgotten certificate: %v", err)
	}
}

func TestJobLifecycle(t *testing.T) { testJobLifecycle(t, NewMemory()) }

func testJobLifecycle(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := Tenant{ID: ids.NewUUID(), Name: "t"}
	if err := s.CreateTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	agent := Agent{TenantID: tenant.ID, ID: ids.NewUUID(), Status: AgentActive, Host: HostInfo{Hostname: "pc"},
		CertFingerprint: "fp", CertNotAfter: time.Now().Add(time.Hour)}
	if err := s.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	mod := Module{Version: "1.0.0", KeyID: "k", Manifest: []byte("{}"),
		Signature: []byte("s"), ManifestSHA256: make([]byte, 32), Archive: []byte("zip")}
	mod.ID = "mod-" + strings.ToLower(ids.NewUUID()[:8])
	if err := s.PutModule(ctx, mod); err != nil {
		t.Fatal(err)
	}
	if err := s.PutModule(ctx, mod); err != ErrModuleExists {
		t.Fatalf("republish: %v", err)
	}

	woke := make(chan string, 4)
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.ListenJobs(lctx, func(k string) { woke <- k })
	time.Sleep(200 * time.Millisecond) // let the listener start

	now := time.Now()
	job := Job{TenantID: tenant.ID, ID: ids.NewUUID(), AgentID: agent.ID, Module: mod.ID, ModuleVersion: "1.0.0",
		Action: "run", Params: []byte(`{"a":1}`), Envelope: []byte("env"), CreatedBy: "t", ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	select {
	case k := <-woke:
		if k != WakeKey(tenant.ID, agent.ID) {
			t.Fatalf("wake key %q", k)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no wake-up for the new job")
	}
	expired := job
	expired.ID, expired.ExpiresAt = ids.NewUUID(), now.Add(-time.Second)
	if err := s.CreateJob(ctx, expired); err != nil {
		t.Fatal(err)
	}
	d, err := s.DispatchableJobs(ctx, tenant.ID, agent.ID, now)
	if err != nil || len(d) != 1 || d[0].ID != job.ID {
		t.Fatalf("dispatchable = %v, %v", d, err)
	}
	if err := s.MarkJobSent(ctx, tenant.ID, job.ID, now); err != nil {
		t.Fatal(err)
	}
	// Sent but unanswered jobs stay dispatchable (re-sent after reconnects).
	if d, _ := s.DispatchableJobs(ctx, tenant.ID, agent.ID, now); len(d) != 1 || d[0].State != JobSent {
		t.Fatalf("after sent: %v", d)
	}
	if err := s.UpdateJob(ctx, tenant.ID, agent.ID, job.ID, JobUpdate{State: JobRunning, Progress: 40}, now); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.DispatchableJobs(ctx, tenant.ID, agent.ID, now); len(d) != 0 {
		t.Fatalf("running job still dispatchable: %v", d)
	}
	// Another agent cannot update this job.
	if err := s.UpdateJob(ctx, tenant.ID, ids.NewUUID(), job.ID, JobUpdate{State: JobFailed}, now); err != ErrNotFound {
		t.Fatalf("foreign update: %v", err)
	}
	if err := s.UpdateJob(ctx, tenant.ID, agent.ID, job.ID, JobUpdate{State: JobSucceeded, Progress: 100, Result: []byte(`{"ok":true}`)}, now); err != nil {
		t.Fatal(err)
	}
	// Duplicate final update (outbox resend) is accepted, a different one is not.
	if err := s.UpdateJob(ctx, tenant.ID, agent.ID, job.ID, JobUpdate{State: JobSucceeded, Result: []byte(`{"ok":true}`)}, now); err != nil {
		t.Fatalf("duplicate final: %v", err)
	}
	if err := s.UpdateJob(ctx, tenant.ID, agent.ID, job.ID, JobUpdate{State: JobFailed}, now); err != ErrJobFinal {
		t.Fatalf("update after final: %v", err)
	}
	got, err := s.GetJob(ctx, tenant.ID, job.ID)
	if err != nil || got.State != JobSucceeded || got.FinishedAt == nil || !strings.Contains(string(got.Result), "ok") {
		t.Fatalf("job = %+v, %v", got, err)
	}
	if list, _ := s.ListJobs(ctx, tenant.ID, agent.ID, 10); len(list) != 2 {
		t.Fatalf("list = %d jobs", len(list))
	}
}

func TestReleases(t *testing.T) { testReleases(t, NewMemory()) }

func testReleases(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := Tenant{ID: ids.NewUUID(), Name: "t"}
	s.CreateTenant(ctx, tenant)
	agent := Agent{TenantID: tenant.ID, ID: ids.NewUUID(), Status: AgentActive, Host: HostInfo{Hostname: "pc"},
		CertFingerprint: "fp", CertNotAfter: time.Now().Add(time.Hour)}
	if err := s.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	// Releases are global: use a version unique to this run.
	v := fmt.Sprintf("9.%d.%d", time.Now().Unix()%100000, time.Now().Nanosecond()%100000)
	r := Release{Version: v, Platform: "windows/amd64", KeyID: "k", Manifest: []byte("{}"), Signature: []byte("s"),
		Files: map[string][]byte{"openrmm-agent.exe": []byte("a"), "openrmm-watchdog.exe": []byte("w")}}
	if err := s.PutRelease(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRelease(ctx, r); err != ErrReleaseExists {
		t.Fatalf("republish: %v", err)
	}
	if d, err := s.GetReleaseFile(ctx, v, "windows/amd64", "openrmm-agent.exe"); err != nil || string(d) != "a" {
		t.Fatalf("file: %q %v", d, err)
	}
	if err := s.SetReleaseTarget(ctx, ReleaseTarget{TenantID: tenant.ID, Ring: RingPilot, Platform: "windows/amd64", Version: "0.0.1"}); err != ErrNotFound {
		t.Fatalf("target to unpublished release: %v", err)
	}
	if err := s.SetReleaseTarget(ctx, ReleaseTarget{TenantID: tenant.ID, Ring: RingPilot, Platform: "windows/amd64", Version: v}); err != nil {
		t.Fatal(err)
	}
	if tg, err := s.GetReleaseTarget(ctx, tenant.ID, RingPilot, "windows/amd64"); err != nil || tg.Version != v {
		t.Fatalf("target: %+v %v", tg, err)
	}
	if _, err := s.GetReleaseTarget(ctx, tenant.ID, RingBroad, "windows/amd64"); err != ErrNotFound {
		t.Fatalf("broad target: %v", err)
	}
	if err := s.SetAgentRing(ctx, tenant.ID, agent.ID, RingPilot); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAgentUpdate(ctx, tenant.ID, agent.ID, AgentUpdate{State: "staged", Version: v, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	a, _ := s.GetAgent(ctx, tenant.ID, agent.ID)
	if a.UpdateRing != RingPilot || a.Update.State != "staged" || a.Update.Version != v {
		t.Fatalf("agent = %+v", a)
	}
}

func TestPolicyVersions(t *testing.T) { testPolicyVersions(t, NewMemory()) }

func testPolicyVersions(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := Tenant{ID: ids.NewUUID(), Name: "t"}
	s.CreateTenant(ctx, tenant)
	agent := Agent{TenantID: tenant.ID, ID: ids.NewUUID(), Status: AgentActive, Host: HostInfo{Hostname: "pc"},
		CertFingerprint: "fp", CertNotAfter: time.Now().Add(time.Hour)}
	s.CreateAgent(ctx, agent)
	id := ids.NewUUID()
	add := func(v int64, deleted bool) error {
		pv := PolicyVersion{TenantID: tenant.ID, ID: id, Version: v, Name: "p", AppliesTo: "all", Deleted: deleted, CreatedBy: "t"}
		if !deleted {
			pv.Document, pv.Envelope = []byte(fmt.Sprintf(`{"v":%d}`, v)), []byte("env")
		}
		return s.AddPolicyVersion(ctx, pv)
	}
	if err := add(1, false); err != nil {
		t.Fatal(err)
	}
	if err := add(1, false); err != ErrPolicyVersion {
		t.Fatalf("duplicate version: %v", err)
	}
	if err := add(3, false); err != ErrPolicyVersion {
		t.Fatalf("skipped version: %v", err)
	}
	if err := add(2, false); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.CurrentPolicies(ctx, tenant.ID)
	if len(cur) != 1 || cur[0].Version != 2 || string(cur[0].Document) != `{"v":2}` {
		t.Fatalf("current = %+v", cur)
	}
	if other, _ := s.CurrentPolicies(ctx, ids.NewUUID()); len(other) != 0 {
		t.Fatal("policy visible from another tenant")
	}
	now := time.Now()
	r := PolicyResult{TenantID: tenant.ID, AgentID: agent.ID, PolicyID: id, RuleID: "r", PolicyVersion: 2,
		RunID: ids.NewUUID(), State: JobSucceeded, Result: []byte(`{"ok":true}`), StartedAt: now, FinishedAt: now}
	if err := s.PutPolicyResult(ctx, r); err != nil {
		t.Fatal(err)
	}
	r2 := r
	r2.RunID, r2.State, r2.Result, r2.Error, r2.FinishedAt = ids.NewUUID(), JobFailed, nil, "boom", now.Add(time.Minute)
	if err := s.PutPolicyResult(ctx, r2); err != nil {
		t.Fatal(err)
	}
	rs, _ := s.ListPolicyResults(ctx, tenant.ID, agent.ID)
	if len(rs) != 1 || rs[0].State != JobFailed || rs[0].Error != "boom" {
		t.Fatalf("results = %+v", rs)
	}
	if err := add(3, true); err != nil {
		t.Fatal(err)
	}
	if cur, _ := s.CurrentPolicies(ctx, tenant.ID); len(cur) != 0 {
		t.Fatal("deleted policy still current")
	}
}

func TestInventories(t *testing.T) { testInventories(t, NewMemory()) }

func testInventories(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := Tenant{ID: ids.NewUUID(), Name: "t"}
	s.CreateTenant(ctx, tenant)
	agent := Agent{TenantID: tenant.ID, ID: ids.NewUUID(), Status: AgentActive, Host: HostInfo{Hostname: "pc"},
		CertFingerprint: "fp", CertNotAfter: time.Now().Add(time.Hour)}
	s.CreateAgent(ctx, agent)
	t0 := time.Now().UTC().Truncate(time.Second)
	inv := func(at time.Time, model string) Inventory {
		return Inventory{TenantID: tenant.ID, AgentID: agent.ID, Data: []byte(`{"model":"` + model + `"}`),
			Summary: InventorySummary{CollectedAt: at, Model: model, SupremoID: "123456789"}}
	}
	if _, err := s.GetInventory(ctx, tenant.ID, agent.ID); err != ErrNotFound {
		t.Fatalf("missing inventory: %v", err)
	}
	if err := s.PutInventory(ctx, inv(t0, "A"), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.PutInventory(ctx, inv(t0.Add(time.Hour), "B"), []InventoryChange{
		{At: t0.Add(time.Hour), Kind: "hardware", Detail: "first"},
		{At: t0.Add(time.Hour), Kind: "hardware", Detail: "second"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutInventory(ctx, inv(t0.Add(time.Minute), "old"), nil); err != ErrStaleInventory {
		t.Fatalf("stale inventory: %v", err)
	}
	got, err := s.GetInventory(ctx, tenant.ID, agent.ID)
	if err != nil || got.Summary.Model != "B" || !got.Summary.CollectedAt.Equal(t0.Add(time.Hour)) ||
		!strings.Contains(string(got.Data), `"B"`) || got.Summary.AgentID != agent.ID {
		t.Fatalf("inventory = %+v, %v", got, err)
	}
	sums, _ := s.InventorySummaries(ctx, tenant.ID)
	if sums[agent.ID].SupremoID != "123456789" {
		t.Fatalf("summaries = %+v", sums)
	}
	if other, _ := s.InventorySummaries(ctx, ids.NewUUID()); len(other) != 0 {
		t.Fatal("inventory visible from another tenant")
	}
	ch, _ := s.ListInventoryChanges(ctx, tenant.ID, agent.ID, 10)
	if len(ch) != 2 || ch[0].Detail != "second" {
		t.Fatalf("changes = %+v", ch)
	}
	if err := s.PutInventory(ctx, Inventory{TenantID: tenant.ID, AgentID: ids.NewUUID(), Data: []byte(`{}`),
		Summary: InventorySummary{CollectedAt: t0}}, nil); err != ErrNotFound {
		t.Fatalf("unknown agent: %v", err)
	}
}

func TestSecurity(t *testing.T) { testSecurity(t, NewMemory()) }

func testSecurity(t *testing.T, s Store) {
	ctx := context.Background()
	tenant := Tenant{ID: ids.NewUUID(), Name: "t"}
	s.CreateTenant(ctx, tenant)
	agent := Agent{TenantID: tenant.ID, ID: ids.NewUUID(), Status: AgentActive, Host: HostInfo{Hostname: "pc"},
		CertFingerprint: "fp", CertNotAfter: time.Now().Add(time.Hour)}
	s.CreateAgent(ctx, agent)
	now := time.Now().UTC().Truncate(time.Second)

	// Settings.
	if cur, err := s.GetSettings(ctx, tenant.ID); err != nil || len(cur.RDPAllowedSubnets) != 0 {
		t.Fatalf("default settings = %+v, %v", cur, err)
	}
	if err := s.PutSettings(ctx, tenant.ID, Settings{RDPAllowedSubnets: []string{"10.0.0.0/8"}}, "t"); err != nil {
		t.Fatal(err)
	}
	if cur, _ := s.GetSettings(ctx, tenant.ID); len(cur.RDPAllowedSubnets) != 1 {
		t.Fatalf("settings = %+v", cur)
	}

	// Checks.
	c := Check{TenantID: tenant.ID, AgentID: agent.ID, CheckID: "trendmicro/sep", Status: CheckOK, Summary: "ok", UpdatedAt: now}
	if prev, err := s.PutCheck(ctx, c); err != nil || prev != "" {
		t.Fatalf("first check: %q %v", prev, err)
	}
	c.Status, c.UpdatedAt = CheckFailing, now.Add(time.Minute)
	if prev, _ := s.PutCheck(ctx, c); prev != CheckOK {
		t.Fatalf("prev = %q", prev)
	}
	old := c
	old.Status, old.UpdatedAt = CheckOK, now.Add(-time.Hour)
	s.PutCheck(ctx, old)
	if cs, _ := s.ListChecks(ctx, tenant.ID, agent.ID); len(cs) != 1 || cs[0].Status != CheckFailing {
		t.Fatalf("checks = %+v", cs)
	}
	if w, _ := s.WorstChecks(ctx, tenant.ID); w[agent.ID] != CheckFailing {
		t.Fatalf("worst = %+v", w)
	}

	// Alerts: merged while open, new after acknowledgement.
	a := Alert{TenantID: tenant.ID, AgentID: agent.ID, Severity: SeverityWarning, Kind: "k", Summary: "one", DedupeKey: "key",
		FirstSeen: now, LastSeen: now}
	if created, err := s.RaiseAlert(ctx, a); err != nil || !created {
		t.Fatalf("raise: %v %v", created, err)
	}
	a.Summary, a.LastSeen = "two", now.Add(time.Minute)
	if created, _ := s.RaiseAlert(ctx, a); created {
		t.Fatal("open alert not merged")
	}
	open, _ := s.ListAlerts(ctx, tenant.ID, "", true, 10)
	if len(open) != 1 || open[0].Count != 2 || open[0].Summary != "two" {
		t.Fatalf("alerts = %+v", open)
	}
	if err := s.AcknowledgeAlert(ctx, tenant.ID, open[0].ID, "op", now); err != nil {
		t.Fatal(err)
	}
	if err := s.AcknowledgeAlert(ctx, tenant.ID, ids.NewUUID(), "op", now); err != ErrNotFound {
		t.Fatalf("unknown alert: %v", err)
	}
	if created, _ := s.RaiseAlert(ctx, a); !created {
		t.Fatal("acknowledged alert reopened instead of a new one")
	}
	once := a
	once.Once = true
	if created, _ := s.RaiseAlert(ctx, once); created {
		t.Fatal("Once alert raised although the key exists")
	}
	once.DedupeKey = "other"
	if created, _ := s.RaiseAlert(ctx, once); !created {
		t.Fatal("Once alert with a new key not raised")
	}
	if all, _ := s.ListAlerts(ctx, tenant.ID, agent.ID, false, 10); len(all) != 3 {
		t.Fatalf("all alerts = %d", len(all))
	}
	if other, _ := s.ListAlerts(ctx, ids.NewUUID(), "", false, 10); len(other) != 0 {
		t.Fatal("alerts visible from another tenant")
	}

	// Logon events: deduplicated, retention, history.
	ev := []LogonEvent{
		{Channel: "security", RecordID: 1, At: now.Add(-48 * time.Hour), EventID: 4624, Kind: "logon", User: "mario", LogonType: 10, SourceIP: "10.0.0.5"},
		{Channel: "security", RecordID: 2, At: now, EventID: 4625, Kind: "logon_failed", User: "x", SourceIP: "10.0.0.9"},
		{Channel: "security", RecordID: 3, At: now.Add(-100 * 24 * time.Hour), EventID: 4624, Kind: "logon", User: "old"},
	}
	added, err := s.AddLogonEvents(ctx, tenant.ID, agent.ID, ev, now)
	if err != nil || len(added) != 2 || added[0].RecordID != 1 {
		t.Fatalf("added = %+v, %v", added, err)
	}
	if again, _ := s.AddLogonEvents(ctx, tenant.ID, agent.ID, ev, now); len(again) != 0 {
		t.Fatalf("duplicates stored: %+v", again)
	}
	first, seen, err := s.LogonHistory(ctx, tenant.ID, agent.ID, "mario", "10.0.0.5", now)
	if err != nil || !seen || !first.Equal(now.Add(-48*time.Hour)) {
		t.Fatalf("history = %v %v %v", first, seen, err)
	}
	if _, seen, _ := s.LogonHistory(ctx, tenant.ID, agent.ID, "mario", "10.0.0.6", now); seen {
		t.Fatal("unknown source reported as seen")
	}
	if list, _ := s.ListLogonEvents(ctx, tenant.ID, agent.ID, 10); len(list) != 2 || list[0].RecordID != 2 {
		t.Fatalf("list = %+v", list)
	}
}
