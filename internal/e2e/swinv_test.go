package e2e

import (
	"html"
	"strings"
	"testing"

	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

func TestSoftwareInventory(t *testing.T) {
	e := startConsole(t)
	zip23 := inventory.Software{Name: "7-Zip", Version: "23.01", Publisher: "Igor Pavlov", Scope: "machine"}
	zip24 := inventory.Software{Name: "7-Zip", Version: "24.08", Publisher: "Igor Pavlov", Scope: "machine"}
	npp := inventory.Software{Name: "Notepad++", Version: "8.6", Publisher: "Notepad++ Team"}
	sys := inventory.Software{Name: "VC Runtime", Version: "14", Publisher: "Microsoft", SystemComponent: true}
	e.addWindowsAgent(t, "PC-01", zip23, npp, sys)
	e.addWindowsAgent(t, "PC-02", zip24)
	e.addWindowsAgent(t, "PC-03", zip24, inventory.Software{Name: "=HYPERLINK(\"x\")", Version: "1"})

	c, _ := e.login(t, admin)
	_, body := get(t, c, e.console.URL+"/reports?tab=software")
	body = html.UnescapeString(body)
	for _, want := range []string{"Produttori più diffusi", "Applicazioni più installate", `<svg class="vbars"`,
		"/reports?pub=Igor+Pavlov&tab=software&title=7-Zip&view=versions", ">7-Zip</a>", "3 righe, dall'ultimo inventario di 3 computer."} {
		if !strings.Contains(body, want) {
			t.Fatalf("titles view: missing %q in %s", want, body)
		}
	}
	if strings.Contains(body, "VC Runtime") {
		t.Fatal("system component listed")
	}
	if _, body = get(t, c, e.console.URL+"/reports?tab=software&all=1"); !strings.Contains(body, "VC Runtime") {
		t.Fatal("all=1 ignored")
	}
	_, body = get(t, c, e.console.URL+"/reports?tab=software&view=versions&pub=Igor+Pavlov&title=7-Zip")
	body = html.UnescapeString(body)
	if !strings.Contains(body, "Versioni più installate") || !strings.Contains(body, "2 righe") || strings.Contains(body, "Notepad") {
		t.Fatalf("versions view: %s", body)
	}
	_, body = get(t, c, e.console.URL+"/reports?tab=software&view=installs&pub=Igor+Pavlov&title=7-Zip&ver=24.08")
	if !strings.Contains(body, "PC-02") || !strings.Contains(body, "PC-03") || strings.Contains(body, "PC-01") {
		t.Fatalf("installs view: %s", body)
	}
	if _, body = get(t, c, e.console.URL+"/reports?tab=software&view=publishers&q=notepad"); !strings.Contains(html.UnescapeString(body), "Notepad++ Team") || strings.Contains(body, "Igor Pavlov") {
		t.Fatalf("publisher search: %s", body)
	}
	_, csv := get(t, c, e.console.URL+"/reports?tab=software&view=titles&format=csv")
	if !strings.HasPrefix(csv, "publisher,title,version,titles,versions,computers,users") || !strings.Contains(csv, "Igor Pavlov,7-Zip,,1,2,3,0") ||
		!strings.Contains(csv, `'=HYPERLINK`) {
		t.Fatalf("csv: %q", csv)
	}
}
