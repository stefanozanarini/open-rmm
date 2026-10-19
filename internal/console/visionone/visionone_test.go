package visionone

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

type fakeV1 struct {
	srv       *httptest.Server
	endpoints []map[string]any
	alerts    []map[string]any
	evilNext  bool
}

func newFake(t *testing.T) *fakeV1 {
	f := &fakeV1{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-key" {
			http.Error(w, `{"error":{"code":"AccessDenied"}}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v3.0/endpointSecurity/endpoints":
			// Two pages: the second through nextLink.
			if r.URL.Query().Get("skipToken") == "" {
				next := f.srv.URL + "/v3.0/endpointSecurity/endpoints?skipToken=2"
				if f.evilNext {
					next = "https://attacker.example/steal"
				}
				json.NewEncoder(w).Encode(map[string]any{"items": f.endpoints[:1], "nextLink": next})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"items": f.endpoints[1:]})
		case "/v3.0/workbench/alerts":
			if r.URL.Query().Get("startDateTime") == "" {
				http.Error(w, "missing start", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"items": f.alerts})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestNewClientRequiresHTTPS(t *testing.T) {
	if _, err := NewClient("http://api.eu.xdr.trendmicro.com", "k", nil); err == nil {
		t.Fatal("plain HTTP accepted")
	}
	if _, err := NewClient("eu", " ", nil); err == nil {
		t.Fatal("empty key accepted")
	}
	c, err := NewClient("EU", "k", nil)
	if err != nil || c.base.Host != "api.eu.xdr.trendmicro.com" {
		t.Fatal(c, err)
	}
}

func TestSync(t *testing.T) {
	ctx := context.Background()
	f := newFake(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	f.endpoints = []map[string]any{
		{"agentGuid": "g1", "endpointName": "PC-01.corp.local",
			"eppAgent":  map[string]any{"status": "on", "version": "14.0.12", "lastConnectedDateTime": now.Add(-48 * time.Hour).Format(time.RFC3339)},
			"edrSensor": map[string]any{"status": "enabled", "connectivity": "disconnected"}},
		{"agentGuid": "g2", "endpointName": "pc-02",
			"eppAgent": map[string]any{"status": "on", "version": "14.0.12", "lastConnectedDateTime": now.Add(-time.Hour).Format(time.RFC3339)}},
	}
	f.alerts = []map[string]any{{"id": "WB-1", "model": "Possible credential dumping", "severity": "high", "score": 80,
		"createdDateTime": now.Add(-time.Hour).Format(time.RFC3339),
		"impactScope":     map[string]any{"entities": []map[string]any{{"entityType": "host", "entityValue": map[string]any{"name": "pc-01", "guid": "g1"}}}}}}

	st := store.NewMemory()
	tenant := ids.NewUUID()
	st.CreateTenant(ctx, store.Tenant{ID: tenant, Name: "t"})
	seen := now.Add(-time.Minute)
	agent := func(name string) string {
		id := ids.NewUUID()
		st.CreateAgent(ctx, store.Agent{TenantID: tenant, ID: id, Status: store.AgentActive, CertFingerprint: id,
			Host: store.HostInfo{Hostname: name, OS: "windows"}, CertNotAfter: now.Add(time.Hour)})
		st.UpdateAgentSeen(ctx, tenant, id, nil, seen, nil)
		return id
	}
	pc1, pc2, pc3 := agent("PC-01"), agent("PC-02"), agent("PC-03")

	c, err := NewClient(f.srv.URL, "secret-key", f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	s := &Syncer{Client: c, Store: st, TenantID: tenant, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	checks := func(agentID string) map[string]store.Check {
		cs, _ := st.ListChecks(ctx, tenant, agentID)
		out := map[string]store.Check{}
		for _, c := range cs {
			out[c.CheckID] = c
		}
		return out
	}
	c1 := checks(pc1)
	if c1["visionone/protection"].Status != store.CheckFailing || c1["visionone/sensor"].Status != store.CheckFailing ||
		c1["visionone/registered"].Status != store.CheckOK {
		t.Fatalf("pc-01 checks = %+v", c1)
	}
	if c2 := checks(pc2); c2["visionone/protection"].Status != store.CheckOK {
		t.Fatalf("pc-02 checks = %+v", c2)
	}
	if c3 := checks(pc3); c3["visionone/registered"].Status != store.CheckWarning {
		t.Fatalf("pc-03 checks = %+v", c3)
	}
	alerts, _ := st.ListAlerts(ctx, tenant, pc1, true, 10)
	var wb *store.Alert
	for i := range alerts {
		if alerts[i].Kind == "visionone.workbench" {
			wb = &alerts[i]
		}
	}
	if wb == nil || wb.Severity != store.SeverityCritical || !strings.Contains(wb.Summary, "WB-1") {
		t.Fatalf("alerts = %+v", alerts)
	}
	// An acknowledged Workbench alert is not raised again by later syncs.
	st.AcknowledgeAlert(ctx, tenant, wb.ID, "op", now)
	s.lastAlerts = time.Time{}
	if err := s.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.ListAlerts(ctx, tenant, pc1, true, 10); len(again) != 0 {
		for _, a := range again {
			if a.Kind == "visionone.workbench" {
				t.Fatalf("workbench alert raised again: %+v", a)
			}
		}
	}

	// A next link to another host is refused (the key would leak).
	f.evilNext = true
	if err := s.Sync(ctx); err == nil || !strings.Contains(err.Error(), "unexpected next link") {
		t.Fatalf("evil next link: %v", err)
	}
	// A wrong key is an error, not an empty inventory.
	bad, _ := NewClient(f.srv.URL, "wrong", f.srv.Client())
	if _, err := bad.Endpoints(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong key: %v", err)
	}
}
