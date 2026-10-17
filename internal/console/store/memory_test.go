package store

import (
	"context"
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
