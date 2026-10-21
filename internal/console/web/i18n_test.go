package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var (
	actionRe = regexp.MustCompile(`(?s)\{\{(.*?)\}\}`)
	// A t, tf or th call with a literal key, inside a template action.
	tmplCallRe = regexp.MustCompile("(?:^|[\\s(])(t|tf|th)\\s+(\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`)")
	verbRe     = regexp.MustCompile(`%[-+# 0]*[0-9]*(?:\.[0-9]+)?[a-zA-Z%]`)
)

// usedKeys returns the literal keys passed to t/tf/th in the templates and to
// T/Tf/tr/trf/trHTML in the Go code, with whether each is a format string.
func usedKeys(t *testing.T) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	names, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		raw, err := fs.ReadFile(assets, n)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range actionRe.FindAllStringSubmatch(string(raw), -1) {
			for _, m := range tmplCallRe.FindAllStringSubmatch(a[1], -1) {
				k, err := strconv.Unquote(m[2])
				if err != nil {
					t.Fatalf("%s: %s: %v", n, m[2], err)
				}
				keys[k] = keys[k] || m[1] == "tf"
			}
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			switch name {
			case "T", "Tf", "tr", "trf", "trHTML":
			default:
				return true
			}
			if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				k, _ := strconv.Unquote(lit.Value)
				keys[k] = keys[k] || name == "Tf" || name == "trf"
			}
			return true
		})
	}
	// Keys translated through variables.
	for _, l := range labels {
		keys[l] = keys[l] || false
	}
	for _, l := range logonTypes {
		keys[l] = keys[l] || false
	}
	for _, l := range resultKeys {
		keys[l] = keys[l] || false
	}
	for _, tb := range tabs {
		keys[tb.Label] = keys[tb.Label] || false
	}
	for _, k := range []string{"Agenti", "Client", "Server", "Patch", "Patch · client", "Patch · server",
		"Nuova policy", "Modifica policy"} {
		keys[k] = keys[k] || false
	}
	return keys
}

func TestCatalogCoversEveryKey(t *testing.T) {
	keys := usedKeys(t)
	if len(keys) < 100 {
		t.Fatalf("only %d keys found: the extraction is broken", len(keys))
	}
	var missing []string
	for k := range keys {
		if _, ok := catalogEN[k]; !ok {
			missing = append(missing, strconv.Quote(k))
		}
	}
	slices.Sort(missing)
	if len(missing) > 0 {
		t.Errorf("%d keys without an English entry:\n%s", len(missing), strings.Join(missing, "\n"))
	}
	var unused []string
	for k := range catalogEN {
		if _, ok := keys[k]; !ok {
			unused = append(unused, strconv.Quote(k))
		}
	}
	slices.Sort(unused)
	if len(unused) > 0 {
		t.Errorf("%d unused catalog entries:\n%s", len(unused), strings.Join(unused, "\n"))
	}
}

func TestCatalogFormatsMatch(t *testing.T) {
	for it, en := range catalogEN {
		if en == "" {
			t.Errorf("%q: empty translation", it)
		}
		if a, b := verbRe.FindAllString(it, -1), verbRe.FindAllString(en, -1); !slices.Equal(a, b) {
			t.Errorf("%q: verbs %v, English %q has %v", it, a, en, b)
		}
		if strings.Count(it, "<") != strings.Count(en, "<") {
			t.Errorf("%q: markup differs in %q", it, en)
		}
	}
}

func TestAcceptLanguage(t *testing.T) {
	for h, want := range map[string]string{
		"":                        langIT,
		"en-US":                   langEN,
		"en-US,en;q=0.9,it;q=0.8": langEN,
		"it-IT,it;q=0.9,en;q=0.8": langIT,
		"de-DE,de;q=0.9,en;q=0.5": langEN,
		"fr-FR":                   langIT,
		"it;q=0.5, EN-gb;q=0.7":   langEN,
		"en;q=0":                  langIT,
		"*":                       langIT,
	} {
		if got := acceptLang(h); got != want {
			t.Errorf("acceptLang(%q) = %s, want %s", h, got, want)
		}
	}
}

func TestTrHTMLEscapesUnknownKeys(t *testing.T) {
	if got := trHTML(langEN, "<b>x</b>"); got != "&lt;b&gt;x&lt;/b&gt;" {
		t.Errorf("trHTML = %q", got)
	}
}

func TestLocalReturn(t *testing.T) {
	for ret, want := range map[string]string{
		"/patches?family=client": "/patches?family=client",
		"//evil.example/":        "/agents",
		"/\\evil.example":        "/agents",
		"https://evil.example/":  "/agents",
		"":                       "/agents",
	} {
		if got := localReturn(ret, "/agents"); got != want {
			t.Errorf("localReturn(%q) = %q", ret, got)
		}
	}
}
