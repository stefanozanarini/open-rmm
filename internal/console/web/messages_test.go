package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTrMessage(t *testing.T) {
	for it, en := range map[string]string{
		"2 aggiornamenti di sicurezza mancanti, 1 usciti da più di 30 giorni":  "2 missing security updates, 1 released more than 30 days ago",
		"2 aggiornamenti di sicurezza mancanti, 1 usciti da piÃ¹ di 30 giorni": "2 missing security updates, 1 released more than 30 days ago",
		"Nessun riavvio in sospeso":                                  "No reboot pending",
		"Trend Micro Standard Endpoint Protection 14.0.21008 attivo": "Trend Micro Standard Endpoint Protection 14.0.21008 active",
		"Trend Vision One Zero Trust Secure Access 2.39.0.1011: installato, nessun servizio noto in esecuzione (verificare i nomi dei servizi)": "Trend Vision One Zero Trust Secure Access 2.39.0.1011: installed, no known service running (check the service names)",
		"Apex One 14: servizio ntrtscan assente, servizio tmlisten Stopped":                                                                     "Apex One 14: service ntrtscan missing, service tmlisten Stopped",
		"Controllo winupdate/updates non superato: 3 aggiornamenti di sicurezza da installare":                                                  "Check winupdate/updates failed: 3 security updates to install",
		"Vision One: Endpoint non presente nell'inventario di Vision One":                                                                       "Vision One: Endpoint not in the Vision One inventory",
		"5 accessi falliti da 10.0.0.9":                                         "5 failed logons from 10.0.0.9",
		"Produttore VMware, Inc. non supportato per gli aggiornamenti firmware": "Manufacturer VMware, Inc. not supported for firmware updates",
		"testo sconosciuto":                                                     "testo sconosciuto",
	} {
		if got := trMessage(langEN, it); got != en {
			t.Errorf("%q\n got %q\nwant %q", it, got, en)
		}
		if got := trMessage(langIT, it); got != it {
			t.Errorf("Italian changed: %q", got)
		}
	}
}

// Every literal check summary of the repository's modules has a
// translation: values are replaced by a placeholder and the sentence must
// change in English.
func TestModuleSummariesTranslated(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "modules", "*", "Main.ps1"))
	if len(files) == 0 {
		t.Fatal("no modules found")
	}
	lit := regexp.MustCompile(`summary = ("(?:[^"]|"")*"|'(?:[^']|'')*')`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range lit.FindAllStringSubmatch(string(b), -1) {
			s := placeholders(m[1])
			if strings.Trim(s, "X:, ") == "" {
				continue // only values (built elsewhere)
			}
			if trMessage(langEN, s) == s {
				t.Errorf("%s: no English for %q", filepath.Base(filepath.Dir(f)), s)
			}
		}
	}
}

// placeholders turns a PowerShell string literal into its text with every
// interpolated value replaced by X.
func placeholders(q string) string {
	body := q[1 : len(q)-1]
	if q[0] == '\'' {
		return strings.ReplaceAll(body, "''", "'")
	}
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		switch {
		case strings.HasPrefix(body[i:], "$("):
			depth := 0
			for j := i + 1; j < len(body); j++ {
				if body[j] == '(' {
					depth++
				} else if body[j] == ')' {
					if depth--; depth == 0 {
						i = j
						break
					}
				}
			}
			b.WriteString("X")
		case strings.HasPrefix(body[i:], "${"):
			i += strings.IndexByte(body[i:], '}')
			b.WriteString("X")
		case body[i] == '$' && i+1 < len(body) && (body[i+1] == '_' || body[i+1] >= 'A' && body[i+1] <= 'z'):
			j := i + 1
			for j < len(body) && (body[j] == '_' || body[j] >= '0' && body[j] <= '9' || body[j] >= 'A' && body[j] <= 'Z' || body[j] >= 'a' && body[j] <= 'z') {
				j++
			}
			i = j - 1
			b.WriteString("X")
		default:
			b.WriteByte(body[i])
		}
	}
	return b.String()
}
