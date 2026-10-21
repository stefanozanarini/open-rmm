package e2e

import (
	"bytes"
	"context"
	"html"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stefanozanarini/open-rmm/internal/console/signer"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/console/web"
)

// Company logo, Active Directory readers, update ring and target version.
func TestConsoleSettingsExtras(t *testing.T) {
	var w *web.Server
	e := startConsole(t, func(cfg *web.Config, _ *signer.Server, _ string) {})
	w = e.web
	ctx := context.Background()
	c, csrf := e.login(t, admin)

	// Logo: raster images only.
	var img bytes.Buffer
	png.Encode(&img, image.NewRGBA(image.Rect(0, 0, 4, 4)))
	send := func(name string, data []byte) string {
		var b bytes.Buffer
		mw := multipart.NewWriter(&b)
		mw.WriteField("csrf", csrf)
		fw, _ := mw.CreateFormFile("logo", name)
		fw.Write(data)
		mw.Close()
		resp, err := c.Post(e.console.URL+"/settings/logo", mw.FormDataContentType(), &b)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return html.UnescapeString(string(out))
	}
	if body := send("logo.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)); !strings.Contains(body, "PNG, JPEG o WebP") {
		t.Fatal("SVG logo accepted")
	}
	if body := send("logo.png", img.Bytes()); !strings.Contains(body, "Logo caricato") || !strings.Contains(body, `<img class="logo" src="/logo"`) {
		t.Fatalf("logo upload: %s", body)
	}
	resp, err := c.Get(e.console.URL + "/logo")
	if err != nil || resp.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("logo: %v %v", err, resp.Header)
	}
	resp.Body.Close()

	// Active Directory reader: the console schedules the collection itself.
	publishTo(t, e.store, filepath.Join(repoRoot(t), "modules", "adinventory"))
	srv := e.addWindowsAgent(t, "FILESRV")
	_, body, _ := post(t, c, e.console.URL+"/agents/"+srv+"/ad-reader", url.Values{"csrf": {csrf}, "on": {"1"}})
	if !strings.Contains(body, "legge Active Directory ogni 24 ore") {
		t.Fatalf("ad reader: %s", body)
	}
	jobs, _ := e.store.ListJobs(ctx, e.tenant, srv, 10)
	if len(jobs) != 1 || jobs[0].Module != "adinventory" {
		t.Fatalf("first reading: %+v", jobs)
	}
	w.RunADReaders(ctx) // read less than 23 hours ago: nothing new
	if jobs, _ = e.store.ListJobs(ctx, e.tenant, srv, 10); len(jobs) != 1 {
		t.Fatalf("reader ran again: %d jobs", len(jobs))
	}

	// Update ring and target version.
	if _, body, _ = post(t, c, e.console.URL+"/agents/"+srv+"/ring", url.Values{"csrf": {csrf}, "ring": {"pilot"}}); !strings.Contains(body, "pilot") {
		t.Fatal("ring not set")
	}
	if a, _ := e.store.GetAgent(ctx, e.tenant, srv); a.UpdateRing != "pilot" {
		t.Fatalf("ring = %s", a.UpdateRing)
	}
	e.store.PutRelease(ctx, store.Release{Version: "1.0.1", Platform: "windows/amd64",
		Files: map[string][]byte{"openrmm-agent.exe": []byte("MZ"), "openrmm-watchdog.exe": []byte("MZ")}})
	_, body, _ = post(t, c, e.console.URL+"/updates/target", url.Values{"csrf": {csrf}, "ring": {"pilot"}, "platform": {"windows/amd64"}, "version": {"1.0.1"}})
	if !strings.Contains(html.UnescapeString(body), "si aggiorneranno alla 1.0.1") {
		t.Fatalf("target: %s", body)
	}
	targets, _ := e.store.ListReleaseTargets(ctx, e.tenant)
	if len(targets) != 1 || targets[0].Version != "1.0.1" || targets[0].Ring != "pilot" {
		t.Fatalf("targets = %+v", targets)
	}
}
