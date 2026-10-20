package modules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Every params.json of the repository's modules matches its manifest.
func TestRepositoryParams(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "modules", "*", ParamsFile))
	if len(files) < 10 {
		t.Fatalf("params files: %v", files)
	}
	for _, f := range files {
		m, err := ReadSource(os.DirFS(filepath.Dir(f)))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(f)
		if _, err := ParseParams(raw, m); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestBuildParams(t *testing.T) {
	m := &Manifest{Actions: map[string]Action{"install": {}}}
	raw := []byte(`{"install": [
	  {"name": "classifications", "type": "multi", "label": {"en": "Classes"}, "options": [{"value": "security"}, {"value": "driver"}]},
	  {"name": "include_kbs", "type": "list", "label": {"en": "KBs"}},
	  {"name": "allow_managed", "type": "bool", "label": {"en": "Managed"}},
	  {"name": "minutes", "type": "int", "label": {"en": "Minutes"}, "min": 0, "max": 60},
	  {"name": "severity", "type": "enum", "label": {"en": "Severity"}, "options": [{"value": "all"}, {"value": "critical"}]}]}`)
	sch, err := ParseParams(raw, m)
	if err != nil {
		t.Fatal(err)
	}
	form := map[string][]string{"classifications": {"security", "driver"}, "include_kbs": {"KB1\nKB2, KB3"},
		"minutes": {"15"}, "severity": {"critical"}}
	got, err := BuildParams(sch["install"], func(n string) []string { return form[n] })
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"classifications": []string{"security", "driver"}, "include_kbs": []string{"KB1", "KB2", "KB3"},
		"allow_managed": false, "minutes": int64(15), "severity": "critical"}
	if !reflect.DeepEqual(got, want) {
		gj, _ := json.Marshal(got)
		t.Fatalf("params = %s", gj)
	}
	for name, bad := range map[string]map[string][]string{
		"out of range":  {"minutes": {"61"}},
		"not a number":  {"minutes": {"x"}},
		"unknown enum":  {"severity": {"none"}},
		"unknown multi": {"classifications": {"evil"}},
	} {
		if _, err := BuildParams(sch["install"], func(n string) []string { return bad[n] }); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseParams([]byte(`{"other": []}`), m); err == nil {
		t.Error("unknown action accepted")
	}
}
