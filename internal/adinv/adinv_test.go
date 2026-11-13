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

func TestUsers(t *testing.T) {
	raw := `{"schema":1,"domain":"corp.local","collected_at":"2026-11-13T10:00:00Z","computers":[],"users":[
	 {"sam":"mario.rossi","upn":"mario.rossi@corp.it","given_name":"Mario","surname":"Rossi","display_name":"Rossi Mario - Contabilità"},
	 {"sam":"anna","given_name":"Anna","surname":"Verdi"},
	 {"sam":"","display_name":"no account"},
	 {"sam":"bad","display_name":"a\u0000b"}]}`
	s, err := Parse([]byte(raw))
	if err != nil || len(s.Users) != 2 {
		t.Fatalf("users = %+v, %v", s, err)
	}
	idx := NewUserIndex([]*Snapshot{s})
	for _, name := range []string{`CORP\Mario.Rossi`, "mario.rossi@corp.it", "MARIO.ROSSI", "mario.rossi@corp.local"} {
		if u, ok := idx.Lookup(name); !ok || u.SAM != "mario.rossi" {
			t.Errorf("Lookup(%q) = %+v, %v", name, u, ok)
		}
	}
	if _, ok := idx.Lookup(`CORP\luigi`); ok {
		t.Error("unknown user found")
	}
	u, _ := idx.Lookup("anna")
	if u.Label() != "Anna Verdi" || strings.Join(u.Names(), "|") != "Anna|Verdi" {
		t.Errorf("anna: %q %q", u.Label(), u.Names())
	}
	u, _ = idx.Lookup("mario.rossi")
	if strings.Join(u.Names(), "|") != "Rossi Mario - Contabilità" {
		t.Errorf("names = %q", u.Names())
	}
}
