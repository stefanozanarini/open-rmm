package policy

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/ids"
)

func valid() *Policy {
	return &Policy{ID: ids.NewUUID(), TenantID: ids.NewUUID(), Name: "Security baseline", Version: 1, AppliesTo: AppliesAll,
		Rules: []Rule{{ID: "inventory", Module: "sysinfo", ModuleVersion: "1.0.0", ModuleSHA256: hex.EncodeToString(make([]byte, 32)),
			Action: "info", Params: json.RawMessage(`{ "a" : 1 }`), EverySeconds: 3600,
			When: &Condition{All: []Condition{{OSFamily: "server"}, {Not: &Condition{ServiceExists: "x"}}}}}}}
}

func TestCanonicalRoundTrip(t *testing.T) {
	p := valid()
	raw, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := q.Canonical()
	if string(raw) != string(raw2) {
		t.Fatalf("not canonical:\n%s\n%s", raw, raw2)
	}
	if AuthNonce(raw) == AuthNonce(append(raw[:len(raw)-1:len(raw)-1], ' ')) {
		t.Fatal("nonce does not depend on the document")
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]func(*Policy){
		"bad applies":    func(p *Policy) { p.AppliesTo = "everyone" },
		"too frequent":   func(p *Policy) { p.Rules[0].EverySeconds = 10 },
		"bad hash":       func(p *Policy) { p.Rules[0].ModuleSHA256 = "zz" },
		"dup rule":       func(p *Policy) { p.Rules = append(p.Rules, p.Rules[0]) },
		"two tests":      func(p *Policy) { p.Rules[0].When = &Condition{ServiceExists: "a", FileExists: "/b"} },
		"empty test":     func(p *Policy) { p.Rules[0].When = &Condition{} },
		"bad family":     func(p *Policy) { p.Rules[0].When = &Condition{OSFamily: "laptop"} },
		"registry hive":  func(p *Policy) { p.Rules[0].When = &Condition{RegistryKeyExists: `HKCU\Software`} },
		"params array":   func(p *Policy) { p.Rules[0].Params = json.RawMessage(`[1]`) },
		"version zero":   func(p *Policy) { p.Version = 0 },
		"path traversal": func(p *Policy) { p.Rules[0].When = &Condition{FileExists: `C:\a\..\b`} },
	}
	for name, mutate := range cases {
		p := valid()
		mutate(p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	deep := &Condition{OSFamily: "client"}
	for range 6 {
		deep = &Condition{Not: deep}
	}
	p := valid()
	p.Rules[0].When = deep
	if p.Validate() == nil {
		t.Error("deeply nested condition accepted")
	}
}

func TestWindow(t *testing.T) {
	at := func(s string) time.Time { v, _ := time.Parse("2006-01-02 15:04 Mon", s); return v }
	day := &Window{Days: []string{"mon", "fri"}, Start: "12:30", End: "14:00"}
	night := &Window{Days: []string{"sat"}, Start: "22:00", End: "05:00"}
	cases := []struct {
		w    *Window
		t    string
		want bool
	}{
		{day, "2026-10-19 12:30 Mon", true},
		{day, "2026-10-19 14:00 Mon", false},
		{day, "2026-10-20 13:00 Tue", false},
		{night, "2026-10-24 23:00 Sat", true},
		{night, "2026-10-25 04:59 Sun", true}, // started on Saturday
		{night, "2026-10-25 23:00 Sun", false},
		{night, "2026-10-24 04:00 Sat", false}, // the Friday night is not in the window
		{nil, "2026-10-24 04:00 Sat", true},
	}
	for _, c := range cases {
		if got := c.w.Contains(at(c.t)); got != c.want {
			t.Errorf("%v at %s = %v", c.w, c.t, got)
		}
	}
	for _, bad := range []Window{{Start: "25:00", End: "01:00"}, {Start: "10:00", End: "10:00"}, {Days: []string{"monday"}, Start: "1:00", End: "02:00"},
		{Days: []string{"mon", "mon"}, Start: "01:00", End: "02:00"}} {
		if err := bad.validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
