package workflow

import (
	"strings"
	"testing"
)

const pkg = "ab00000000000000000000000000000000000000000000000000000000000000"

func TestParse(t *testing.T) {
	raw := `{"detection":{"rules":[{"type":"app","name":"7-Zip*","op":"version_ge","value":"24.08"}]},
	 "steps":[
	  {"type":"script","when":{"match":"any","rules":[{"type":"user_group","name":"CORP\\Contabilità"},{"type":"computer_group","name":"PC-Ufficio"}]},"script":"Stop-Process -Name 7zFM"},
	  {"type":"download","url":"https://example.com/7z.msi","save_as":"7z.msi","sha256":"` + strings.ToUpper(pkg) + `"},
	  {"type":"install","file":"7z.msi"},
	  {"type":"install","package":"` + pkg + `","kind":"nullsoft"},
	  {"type":"download","package":"` + pkg + `","save_as":"C:\\ProgramData\\x.cfg"},
	  {"type":"http","method":"post","url":"https://hooks.example.com/x","headers":"X-Token: a\nAccept: */*","body":"{}"}]}`
	d, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if d.Detection.Match != "all" || d.Steps[0].When.Match != "any" || d.Steps[1].SHA256 != pkg || d.Steps[5].Method != "POST" {
		t.Fatalf("not normalized: %+v", d)
	}
	if got := d.Packages(); len(got) != 1 || got[0] != pkg {
		t.Fatalf("packages = %v", got)
	}
}

func TestParseRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"no steps":         `{"steps":[]}`,
		"unknown field":    `{"steps":[{"type":"script","script":"x","oops":1}]}`,
		"unknown step":     `{"steps":[{"type":"reboot"}]}`,
		"empty script":     `{"steps":[{"type":"script","script":" "}]}`,
		"file url":         `{"steps":[{"type":"download","url":"file:///c:/x","save_as":"x"}]}`,
		"url and package":  `{"steps":[{"type":"download","url":"https://x/y","package":"` + pkg + `","save_as":"x"}]}`,
		"url without name": `{"steps":[{"type":"download","url":"https://x/y"}]}`,
		"bad package":      `{"steps":[{"type":"install","package":"abc"}]}`,
		"install nothing":  `{"steps":[{"type":"install"}]}`,
		"bad kind":         `{"steps":[{"type":"install","file":"a.exe","kind":"zip"}]}`,
		"http put":         `{"steps":[{"type":"http","method":"PUT","url":"https://x"}]}`,
		"bad header":       `{"steps":[{"type":"http","url":"https://x","headers":"no colon"}]}`,
		"bad match":        `{"detection":{"match":"xor"},"steps":[{"type":"script","script":"x"}]}`,
		"registry root":    `{"detection":{"rules":[{"type":"registry","path":"SOFTWARE\\x","op":"exists"}]},"steps":[{"type":"script","script":"x"}]}`,
		"op":               `{"detection":{"rules":[{"type":"file","path":"c:\\x","op":"equals","value":"1"}]},"steps":[{"type":"script","script":"x"}]}`,
		"no value":         `{"detection":{"rules":[{"type":"app","name":"x","op":"version_ge"}]},"steps":[{"type":"script","script":"x"}]}`,
		"no group":         `{"steps":[{"type":"script","script":"x","when":{"rules":[{"type":"user_group"}]}}]}`,
		"control chars":    `{"steps":[{"type":"command","command":"a\u0000b"}]}`,
		"timeout":          `{"steps":[{"type":"script","script":"x","timeout_seconds":99999}]}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
