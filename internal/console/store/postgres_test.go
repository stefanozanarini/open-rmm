package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stefanozanarini/open-rmm/internal/console/audit"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

// Integration tests run only when OPENRMM_TEST_DATABASE_URL points to a
// disposable database (see Makefile target test-integration).
func openTestDB(t *testing.T) *Postgres {
	t.Helper()
	url := os.Getenv("OPENRMM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("OPENRMM_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := OpenPostgres(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// Migrations are idempotent.
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestPostgresAuditChain(t *testing.T)            { testAuditChain(t, openTestDB(t)) }
func TestPostgresEnrollmentTokenLimits(t *testing.T) { testEnrollmentTokenLimits(t, openTestDB(t)) }
func TestPostgresApprovalAndRotation(t *testing.T)   { testApprovalAndRotation(t, openTestDB(t)) }
func TestPostgresJobLifecycle(t *testing.T)          { testJobLifecycle(t, openTestDB(t)) }
func TestPostgresReleases(t *testing.T)              { testReleases(t, openTestDB(t)) }
func TestPostgresPolicyVersions(t *testing.T)        { testPolicyVersions(t, openTestDB(t)) }
func TestPostgresInventories(t *testing.T)           { testInventories(t, openTestDB(t)) }
func TestPostgresSecurity(t *testing.T)              { testSecurity(t, openTestDB(t)) }
func TestPostgresUpdateStatus(t *testing.T)          { testUpdateStatus(t, openTestDB(t)) }
func TestPostgresPackagesAndCatalog(t *testing.T)    { testPackagesAndCatalog(t, openTestDB(t)) }
func TestPostgresSitesAndNotes(t *testing.T)         { testSitesAndNotes(t, openTestDB(t)) }

func TestPostgresTenantIsolation(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	a, b := Tenant{ID: ids.NewUUID(), Name: "A"}, Tenant{ID: ids.NewUUID(), Name: "B"}
	for _, tn := range []Tenant{a, b} {
		if err := db.CreateTenant(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	agent := Agent{TenantID: a.ID, ID: ids.NewUUID(), Status: AgentActive, Host: HostInfo{Hostname: "pc01"},
		CertFingerprint: "fp", CertNotAfter: time.Now().Add(time.Hour)}
	if err := db.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetAgent(ctx, a.ID, agent.ID); err != nil {
		t.Fatalf("own tenant: %v", err)
	}
	if _, err := db.GetAgent(ctx, b.ID, agent.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other tenant sees agent: %v", err)
	}
	// Writing a row for tenant A while scoped to tenant B must fail.
	err := db.inTenant(ctx, b.ID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agents (tenant_id, id, status, cert_fingerprint, cert_not_after)
			VALUES ($1, $2, 'active', 'x', now())`, a.ID, ids.NewUUID())
		return err
	})
	if err == nil {
		t.Fatal("cross-tenant insert allowed")
	}
	// Without a tenant set, nothing is visible.
	var n int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("unscoped query sees %d agents", n)
	}
	ip := mustAddr(t, "192.0.2.10")
	if err := db.UpdateAgentSeen(ctx, a.ID, agent.ID, nil, time.Now(), &ip); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetAgent(ctx, a.ID, agent.ID)
	if err != nil || got.LastSeenIP == nil || *got.LastSeenIP != ip {
		t.Fatalf("last seen ip = %v, %v", got.LastSeenIP, err)
	}
}

func TestPostgresAuditIsAppendOnly(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	tn := Tenant{ID: ids.NewUUID(), Name: "T"}
	if err := db.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AppendAudit(ctx, audit.Event{TenantID: tn.ID, Actor: "t", Action: "x"}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE audit_log SET actor = 'evil'`, `DELETE FROM audit_log`} {
		err := db.inTenant(ctx, tn.ID, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, q); return err })
		if err == nil {
			t.Errorf("%q succeeded", q)
		}
	}
}
