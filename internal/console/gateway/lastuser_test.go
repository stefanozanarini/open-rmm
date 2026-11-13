package gateway

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/pki"
)

func TestLastUser(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	tenant := ids.NewUUID()
	st.CreateTenant(ctx, store.Tenant{ID: tenant, Name: "t"})
	root, _ := pki.NewRootCA("r", time.Now())
	ca, _ := pki.NewIntermediateCA(root, "a", time.Now())
	now := time.Now().UTC().Truncate(time.Second)
	s, err := New(Config{Store: st, AgentsCA: ca, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	a := store.Agent{TenantID: tenant, ID: ids.NewUUID(), Status: store.AgentActive, Host: store.HostInfo{Hostname: "PC-01"},
		CertFingerprint: "fp", CertNotAfter: now.Add(time.Hour)}
	st.CreateAgent(ctx, a)
	inv := func(at time.Time, user string) []byte {
		return []byte(fmt.Sprintf(`{"schema":1,"collected_at":%q,"os":{"logged_on_user":%q}}`, at.Format(time.RFC3339), user))
	}
	last := func() store.LastUser {
		m, _ := st.LastUsers(ctx, tenant)
		return m[a.ID]
	}

	s.ingestInventory(ctx, a, inv(now.Add(-48*time.Hour), `CORP\mario`))
	if u := last(); u.User != `CORP\mario` || u.Source != store.LastUserInventory {
		t.Fatalf("after inventory: %+v", u)
	}
	// Nobody logged on at the next inventory: the last user stays.
	s.ingestInventory(ctx, a, inv(now.Add(-24*time.Hour), ""))
	if u := last(); u.User != `CORP\mario` {
		t.Fatalf("lost on an empty inventory: %+v", u)
	}
	// An RDP logon, after Window Manager and computer-account logons that
	// must not count.
	logons := fmt.Sprintf(`{"events":[
	 {"channel":"security","record_id":1,"time":%q,"event_id":4624,"kind":"logon","user":"luigi","domain":"CORP","logon_type":10,"source_ip":"192.168.1.5"},
	 {"channel":"security","record_id":2,"time":%q,"event_id":4624,"kind":"logon","user":"DWM-3","domain":"Window Manager","logon_type":2},
	 {"channel":"security","record_id":3,"time":%q,"event_id":4624,"kind":"logon","user":"PC-01$","domain":"CORP","logon_type":3},
	 {"channel":"security","record_id":4,"time":%q,"event_id":4625,"kind":"logon_failed","user":"anna","domain":"CORP","logon_type":2}]}`,
		now.Add(-2*time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339),
		now.Add(-time.Hour).Format(time.RFC3339), now.Add(-time.Minute).Format(time.RFC3339))
	s.ingestLogons(ctx, a, []byte(logons))
	if u := last(); u.User != `CORP\luigi` || u.Source != store.LastUserLogon || !u.SeenAt.Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("after logons: %+v", u)
	}
	// An older inventory (re-sent) does not go back to mario.
	s.ingestInventory(ctx, a, inv(now.Add(-72*time.Hour), `CORP\mario`))
	if u := last(); u.User != `CORP\luigi` {
		t.Fatalf("older inventory won: %+v", u)
	}
}
