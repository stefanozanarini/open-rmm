package adinv

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseAndAnalyze(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	day := func(n int) string { return now.Add(-time.Duration(n) * 24 * time.Hour).Format(time.RFC3339) }
	raw := fmt.Sprintf(`{"schema":1,"domain":"Corp.Local.","collected_at":%q,"computers":[
	 {"name":"pc-01$","dn":"CN=PC-01,OU=Computer,OU=Bologna,OU=Sedi,DC=corp,DC=local","enabled":true,"last_logon":%q},
	 {"name":"PC-02","dn":"CN=PC-02,OU=Computer,OU=Bologna,OU=Sedi,DC=corp,DC=local","enabled":true,"last_logon":%q},
	 {"name":"OLD-PC","dn":"CN=OLD-PC,CN=Computers,DC=corp,DC=local","enabled":true,"last_logon":%q},
	 {"name":"GONE","dn":"CN=GONE,OU=Dismessi\\, 2024,DC=corp,DC=local","enabled":false,"last_logon":%q},
	 {"name":"NEW","dn":"CN=NEW,CN=Computers,DC=corp,DC=local","enabled":true,"created":%q},
	 {"name":"bad name!","dn":"CN=x"}]}`, day(0), day(1), day(3), day(200), day(400), day(2))
	s, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if s.Domain != "corp.local" || len(s.Computers) != 5 || s.Computers[3].Name != "PC-01" {
		t.Fatalf("snapshot = %+v", s)
	}
	idx := NewIndex([]*Snapshot{s})
	if got := idx["PC-01"].OU(); got != "Sedi/Bologna/Computer" {
		t.Errorf("OU = %q", got)
	}
	if got := idx["GONE"].OU(); got != "Dismessi, 2024" {
		t.Errorf("escaped OU = %q", got)
	}
	if got := idx["OLD-PC"].OU(); got != "Computers" {
		t.Errorf("container = %q", got)
	}
	r := Analyze(s, map[string]bool{HostKey("pc-01.corp.local"): true}, now)
	var without, stale []string
	for _, c := range r.WithoutAgent {
		without = append(without, c.Name)
	}
	for _, c := range r.Stale {
		stale = append(stale, c.Name)
	}
	if r.Total != 5 || r.Enabled != 4 || r.WithAgent != 1 || strings.Join(without, ",") != "NEW,PC-02" || strings.Join(stale, ",") != "OLD-PC" {
		t.Fatalf("report = %+v without=%v stale=%v", r, without, stale)
	}
	if d := idx["OLD-PC"].IdleDays(now); d != 200 {
		t.Errorf("idle days = %d", d)
	}
}

func TestParseRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"schema": `{"schema":2,"domain":"corp.local","collected_at":"2026-01-01T00:00:00Z"}`,
		"domain": `{"schema":1,"domain":"corp local","collected_at":"2026-01-01T00:00:00Z"}`,
		"time":   `{"schema":1,"domain":"corp.local"}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
