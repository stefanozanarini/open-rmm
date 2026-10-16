package store

import (
	"context"
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
