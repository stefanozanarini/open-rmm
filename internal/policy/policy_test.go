package policy

import (
	"encoding/hex"
	"encoding/json"
	"testing"

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
