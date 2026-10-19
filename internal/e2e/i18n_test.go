package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// acceptLanguage adds an Accept-Language header to every request.
type acceptLanguage struct {
	base http.RoundTripper
	lang string
}

func (a acceptLanguage) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Accept-Language", a.lang)
	return a.base.RoundTrip(r)
}

// loginWithLanguage signs in with a browser that sends Accept-Language.
func (e *consoleEnv) loginWithLanguage(t *testing.T, u opIdentity, lang string) (*http.Client, string) {
	t.Helper()
	e.idp.signIn(u)
	c := e.browser(t)
	c.Transport = acceptLanguage{base: c.Transport, lang: lang}
	code, body := get(t, c, e.console.URL+"/agents")
	if code != 200 || !strings.Contains(body, "pc01") {
		t.Fatalf("login: %d %s", code, body)
	}
	return c, csrfFrom(t, body)
}

func TestConsoleLanguages(t *testing.T) {
	e := startConsole(t)

	// Without Accept-Language the console is in Italian.
	c, csrf := e.login(t, admin)
	_, body := get(t, c, e.console.URL+"/agents")
	if !strings.Contains(body, `<html lang="it"`) || !strings.Contains(body, "Tutti gli agenti") || !strings.Contains(body, `<option value="it" lang="it" selected>`) {
		t.Fatal("default language is not Italian")
	}

	// The browser's language applies until the operator chooses one.
	ec, ecsrf := e.loginWithLanguage(t, admin, "en-US,en;q=0.9")
	_, body = get(t, ec, e.console.URL+"/agents")
	if !strings.Contains(body, `<html lang="en"`) || !strings.Contains(body, "All agents") || !strings.Contains(body, "Awaiting approval (1)") ||
		strings.Contains(body, "Tutti gli agenti") {
		t.Fatal("Accept-Language en-US not applied")
	}
	if _, body = get(t, ec, e.console.URL+"/patches"); !strings.Contains(body, "Patches") || !strings.Contains(body, "Most widespread applications to update") {
		t.Fatal("patches page not in English")
	}

	// Messages for an unauthenticated browser follow Accept-Language too.
	anon := e.browser(t)
	anon.Transport = acceptLanguage{base: anon.Transport, lang: "en"}
	if code, body, _ := post(t, anon, e.console.URL+"/theme", url.Values{"theme": {"dark"}}); code != http.StatusUnauthorized || !strings.Contains(body, "session expired") {
		t.Fatalf("anonymous error: %d %s", code, body)
	}

	// The choice is kept in the session and overrides the browser; the
	// return target stays inside the console.
	code, body, final := post(t, c, e.console.URL+"/lang", url.Values{"csrf": {csrf}, "lang": {"en"}, "return": {"/patches?family=client"}})
	if code != 200 || final.RequestURI() != "/patches?family=client" || !strings.Contains(body, `<html lang="en"`) || !strings.Contains(body, "Patches · clients") {
		t.Fatalf("switch to English: %d at %s", code, final)
	}
	if _, body = get(t, c, e.console.URL+"/agents"); !strings.Contains(body, `<html lang="en"`) || !strings.Contains(body, `<option value="en" lang="en" selected>`) {
		t.Fatal("language not kept in the session")
	}
	if _, _, final = post(t, c, e.console.URL+"/lang", url.Values{"csrf": {csrf}, "lang": {"en"}, "return": {"//evil.example/"}}); final.Path != "/agents" || final.Host != strings.TrimPrefix(e.console.URL, "https://") {
		t.Fatalf("language redirect to %s", final)
	}
	if _, body, _ = post(t, ec, e.console.URL+"/lang", url.Values{"csrf": {ecsrf}, "lang": {"it"}}); !strings.Contains(body, `<html lang="it"`) || !strings.Contains(body, "Tutti gli agenti") {
		t.Fatal("session language does not override Accept-Language")
	}
	// Unknown languages are ignored; the CSRF token is required.
	if _, body, _ = post(t, ec, e.console.URL+"/lang", url.Values{"csrf": {ecsrf}, "lang": {"fr"}}); !strings.Contains(body, `<html lang="it"`) {
		t.Fatal("unknown language changed the session")
	}
	if code, _, _ := post(t, ec, e.console.URL+"/lang", url.Values{"lang": {"en"}}); code != http.StatusForbidden {
		t.Fatalf("language changed without CSRF: %d", code)
	}

	// Flash messages are translated when they are created.
	_, body, _ = post(t, c, e.console.URL+"/sites", url.Values{"csrf": {csrf}, "name": {"Bologna"}, "subnets": {"192.168.1.0/24"}})
	if !strings.Contains(body, "Site Bologna saved.") || !strings.Contains(body, "Subnets (one per line)") {
		t.Fatal("flash message not in English")
	}
	_, body, _ = post(t, c, e.console.URL+"/sites", url.Values{"csrf": {csrf}, "name": {"Bologna"}, "subnets": {"192.168.2.0/24"}})
	if !strings.Contains(body, "A site with this name already exists.") {
		t.Fatal("validation message not in English")
	}
	// The Italian operator still sees Italian.
	_, body, _ = post(t, ec, e.console.URL+"/sites", url.Values{"csrf": {ecsrf}, "name": {"Milano"}, "subnets": {"10.0.0.0/8"}})
	if !strings.Contains(body, "Sede Milano salvata.") {
		t.Fatal("Italian flash message")
	}

	// Status labels and dates follow the language.
	_, body = get(t, c, e.console.URL+"/agents/"+e.agentID)
	if !strings.Contains(body, ">pending</span>") || !strings.Contains(body, "Certificate valid until") {
		t.Fatal("agent page not in English")
	}
	_, body = get(t, ec, e.console.URL+"/agents/"+e.agentID)
	if !strings.Contains(body, ">in attesa</span>") {
		t.Fatal("agent page not in Italian")
	}

	// Every page renders in both languages, without formatting errors.
	pages := []string{"/agents", "/agents/" + e.agentID, "/jobs", "/modules", "/policies", "/policies/new",
		"/policies/new?template=baseline", "/patches", "/packages", "/tokens", "/alerts", "/alerts?all=1", "/audit",
		"/updates", "/settings", "/setup", "/sites", "/ad"}
	for _, tab := range []string{"summary", "checks", "patches", "software", "inventory", "logons", "policies", "history", "notes", "commands"} {
		pages = append(pages, "/agents?agent="+e.agentID+"&tab="+tab)
	}
	for _, b := range []*http.Client{c, ec} {
		for _, p := range pages {
			if code, body := get(t, b, e.console.URL+p); code != 200 || strings.Contains(body, "%!") {
				t.Errorf("%s: %d", p, code)
			}
		}
	}
}
