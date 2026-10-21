package web

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJobResultReadable(t *testing.T) {
	raw := []byte(`{"exit_code":3010,"product_code":"{23170F69-40C1-2702-2604-000001000000}","product_name":"7-Zip 26.04 (x64 edition)",
		"product_version":"26.04.00.0","reboot_required":true,"signer":"<b>Igor</b>","signature":"Valid",
		"checks":[{"id":"updates","status":"ok","summary":"Nessun riavvio in sospeso"}],"output":"hidden"}`)
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	if got := jobOutcome(langIT, "software", "install", fields); got != "Installato: 7-Zip 26.04 (x64 edition) 26.04.00.0 · riavvio richiesto per completarla" {
		t.Errorf("outcome = %q", got)
	}
	if got := jobOutcome(langEN, "software", "install", fields); !strings.HasPrefix(got, "Installed: 7-Zip") {
		t.Errorf("English outcome = %q", got)
	}
	h := string(renderResult(langEN, raw, "output"))
	for _, want := range []string{"<dt>exit code</dt><dd>3010 <span class=\"muted\">(succeeded, restart required)</span>",
		"<dt>restart required</dt><dd>yes</dd>", "&lt;b&gt;Igor&lt;/b&gt;", `<span class="badge chk-ok">ok</span>`, "No reboot pending"} {
		if !strings.Contains(h, want) {
			t.Errorf("result lacks %q:\n%s", want, h)
		}
	}
	if strings.Contains(h, "hidden") || strings.Contains(h, "<b>") {
		t.Errorf("output shown or markup not escaped:\n%s", h)
	}
	rows := make([]string, 60)
	for i := range rows {
		rows[i] = `{"title":"u","result":"succeeded"}`
	}
	if h := string(renderResult(langIT, []byte(`{"installed":[`+strings.Join(rows, ",")+`]}`))); !strings.Contains(h, "Mostrate 50 righe su 60.") ||
		strings.Count(h, "<tr>") != 51 || !strings.Contains(h, "<td>completato</td>") {
		t.Errorf("long table:\n%s", h)
	}
}
