package policy

import (
	"encoding/json"
	"testing"

	"github.com/stefanozanarini/open-rmm/internal/ids"
)

func TestBaseline(t *testing.T) {
	tenant := ids.NewUUID()
	hash := "0000000000000000000000000000000000000000000000000000000000000000"
	mods := map[string]ModuleRef{"inventory": {"1.0.0", hash}, "winupdate": {"1.2.0", hash}, "script": {"1.0.0", hash}}
	p := Baseline(tenant, 1, mods)
	if p == nil || len(p.Rules) != 2 || p.Rules[0].Module != "inventory" || p.Rules[1].ModuleVersion != "1.2.0" {
		t.Fatalf("baseline = %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if !ids.IsUUID(p.ID) || p.ID != BaselineID(tenant) || BaselineID(ids.NewUUID()) == p.ID {
		t.Fatalf("id %s", p.ID)
	}
	if err := CheckBaseline(p); err != nil {
		t.Fatal(err)
	}
	if Baseline(tenant, 1, map[string]ModuleRef{"script": {"1.0.0", hash}}) != nil {
		t.Fatal("baseline without collections")
	}
	bad := map[string]func(p *Policy){
		"params":       func(p *Policy) { p.Rules[0].Params = json.RawMessage(`{"x":1}`) },
		"action":       func(p *Policy) { p.Rules[1].Action = "install" },
		"interval":     func(p *Policy) { p.Rules[0].EverySeconds = 60 },
		"window":       func(p *Policy) { p.Rules[0].Window = &Window{Start: "01:00", End: "02:00"} },
		"condition":    func(p *Policy) { p.Rules[0].When = &Condition{OSFamily: "server"} },
		"other module": func(p *Policy) { p.Rules[0].Module, p.Rules[0].ID = "script", "script" },
		"duplicate":    func(p *Policy) { p.Rules = append(p.Rules, p.Rules[0]) },
		"other id":     func(p *Policy) { p.ID = ids.NewUUID() },
		"name":         func(p *Policy) { p.Name = "Altro" },
		"target":       func(p *Policy) { p.AppliesTo = AppliesServers },
	}
	for name, change := range bad {
		q := Baseline(tenant, 1, mods)
		change(q)
		if CheckBaseline(q) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	q := Baseline(tenant, 7, mods)
	if !SameRules(p, q) {
		t.Fatal("version counted as a change")
	}
	mods["inventory"] = ModuleRef{"1.0.1", hash}
	if SameRules(p, Baseline(tenant, 1, mods)) {
		t.Fatal("new module version not detected")
	}
}
