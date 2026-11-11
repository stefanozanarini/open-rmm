package e2e

import (
	"context"
	"encoding/json"
	"html"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stefanozanarini/tempra-rmm/internal/console/signer"
	"github.com/stefanozanarini/tempra-rmm/internal/console/web"
	"github.com/stefanozanarini/tempra-rmm/internal/policy"
)

// The policy editor: module cards with their actions, settings and
// parameters, instead of the JSON.
func TestConsolePolicyEditor(t *testing.T) {
	e := startConsole(t, func(cfg *web.Config, _ *signer.Server, _ string) {
		cfg.ModuleBundle = web.ModuleBundle{Dir: filepath.Join("..", "..", "modules")}
	})
	ctx := context.Background()
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "firmware"))
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "reboot"))
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "script"))
	c, csrf := e.login(t, admin)

	_, body := get(t, c, e.console.URL+"/policies/new")
	for _, want := range []string{`href="/policies">Policy</a>`, `name="on.firmware.install-tool"`, `name="p.reboot.reboot.notice_minutes"`,
		`name="day.reboot.reboot.sat"`, "?mode=json"} {
		if !strings.Contains(body, want) {
			t.Fatalf("editor lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, `name="on.script.`) {
		t.Fatal("ad-hoc script module offered in a policy")
	}

	form := url.Values{"csrf": {csrf}, "name": {"Strumenti"}, "applies_to": {"clients"},
		"on.firmware.install-tool": {"1"}, "every.firmware.install-tool": {"24h"}, "cond.firmware.install-tool": {"client"},
		"on.reboot.reboot": {"1"}, "every.reboot.reboot": {"1h"}, "day.reboot.reboot.sat": {"1"}, "day.reboot.reboot.sun": {"1"},
		"start.reboot.reboot": {"22:00"}, "end.reboot.reboot": {"05:00"}, "p.reboot.reboot.notice_minutes": {"30"},
		"p.reboot.reboot.only_if_pending": {"true"},
		// Not switched on: ignored.
		"every.firmware.scan": {"1h"}}
	// A missing condition value keeps the form as filled in.
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("cond.firmware.install-tool", "service_exists")
	_, body, _ = post(t, c, e.console.URL+"/policies", bad)
	if b := html.UnescapeString(body); !strings.Contains(b, "indica il nome del servizio") || !strings.Contains(b, `name="on.reboot.reboot" value="1" checked`) ||
		!strings.Contains(b, `name="start.reboot.reboot" value="22:00"`) {
		t.Fatalf("invalid form not shown again: %s", b)
	}
	if cur, _ := e.store.CurrentPolicies(ctx, e.tenant); len(cur) != 0 {
		t.Fatal("invalid policy stored")
	}

	if code, _, final := post(t, c, e.console.URL+"/policies", form); code != 200 || final.Path != "/policies" {
		t.Fatalf("save: %d at %s", code, final)
	}
	cur, _ := e.store.CurrentPolicies(ctx, e.tenant)
	if len(cur) != 1 || cur[0].AppliesTo != "clients" {
		t.Fatalf("policies = %+v", cur)
	}
	p, err := policy.Parse(cur[0].Document)
	if err != nil || len(p.Rules) != 2 {
		t.Fatalf("policy = %+v %v", p, err)
	}
	fw, rb := p.Rules[0], p.Rules[1]
	if fw.ID != "firmware-install-tool" || fw.Action != "install-tool" || fw.EverySeconds != 86400 || fw.When == nil || fw.When.OSFamily != "client" {
		t.Fatalf("firmware rule = %+v", fw)
	}
	var params map[string]any
	json.Unmarshal(rb.Params, &params)
	if rb.ID != "reboot-reboot" || rb.EverySeconds != 3600 || rb.Window == nil || rb.Window.Start != "22:00" ||
		strings.Join(rb.Window.Days, ",") != "sat,sun" || params["notice_minutes"] != float64(30) || params["only_if_pending"] != true {
		t.Fatalf("reboot rule = %+v %v", rb, params)
	}

	// Editing shows the saved settings.
	_, body = get(t, c, e.console.URL+"/policies/"+p.ID)
	body = html.UnescapeString(body)
	for _, want := range []string{`name="on.firmware.install-tool" value="1" checked`, `<option value="client" selected>`,
		`name="day.reboot.reboot.sun" value="1" checked`, `name="end.reboot.reboot" value="05:00"`,
		`name="p.reboot.reboot.notice_minutes" value="30"`, "1 attive"} {
		if !strings.Contains(body, want) {
			t.Fatalf("edit form lacks %q: %s", want, body)
		}
	}
}
