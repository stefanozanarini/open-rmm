package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
)

// A file session: approved with MFA, then folders are listed, a file is
// uploaded and downloaded (also as a zip), a folder created; the agent's
// own folders stay out of reach and everything is audited.
func TestConsoleFiles(t *testing.T) {
	e := start(t)
	broker := e.broker(t)
	e.publish(t, filepath.Join(repoRoot(t), "modules", "files"))
	// File sessions do not depend on the shell's local policy.
	cfg := e.agentConfig(t, e.tokenWith(t, 1, true))
	noShell := false
	cfg.AllowInteractiveShell = &noShell
	runAgentVersion(t, cfg, "1.1.0")
	agentID := e.onlyAgent(t).ID
	ce := consoleOn(t, e, broker)
	c, csrf := ce.loginTo(t, admin)

	if _, body := get(t, c, ce.console.URL+"/agents/"+agentID); !strings.Contains(body, `action="/agents/`+agentID+`/files"`) {
		t.Fatal("no files button")
	}
	code, body, final := post(t, c, ce.console.URL+"/agents/"+agentID+"/files", url.Values{"csrf": {csrf}, "minutes": {"30"}})
	if code != 200 || final.Path != "/files" || !strings.Contains(body, `id="files"`) {
		t.Fatalf("open files: %d at %s", code, final)
	}
	jobID := final.Query().Get("job")
	base := ce.console.URL + "/files/" + jobID

	getJSON := func(u string) (int, map[string]any) {
		code, body := get(t, c, u)
		var m map[string]any
		json.Unmarshal([]byte(body), &m)
		return code, m
	}
	// The agent opens the session shortly after the approval.
	var roots map[string]any
	waitFor(t, func() bool {
		code, m := getJSON(base + "/list")
		roots = m
		return code == 200
	})
	if rs, _ := roots["roots"].([]any); len(rs) != 1 || rs[0] != "/" {
		t.Fatalf("roots: %v", roots)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "report.txt"), []byte("hello from the agent"), 0o644)
	code, m := getJSON(base + "/list?path=" + url.QueryEscape(dir))
	if entries, _ := m["entries"].([]any); code != 200 || len(entries) != 1 {
		t.Fatalf("list: %d %v", code, m)
	}

	// Upload, in the order the server reads the fields.
	payload := bytes.Repeat([]byte("tempra "), 100000)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("csrf", csrf)
	mw.WriteField("job", jobID)
	mw.WriteField("dir", dir)
	mw.WriteField("size", strconv.Itoa(len(payload)))
	mw.WriteField("overwrite", "0")
	fw, _ := mw.CreateFormFile("file", "setup.bin")
	fw.Write(payload)
	mw.Close()
	req, _ := http.NewRequest("POST", ce.console.URL+"/files/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", ce.console.URL)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(rb), `"ok":true`) {
		t.Fatalf("upload: %d %s", resp.StatusCode, rb)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "setup.bin")); !bytes.Equal(got, payload) {
		t.Fatal("uploaded file differs")
	}

	// Download, alone and as a zip.
	code, body = get(t, c, base+"/download?path="+url.QueryEscape(filepath.Join(dir, "report.txt")))
	if code != 200 || body != "hello from the agent" {
		t.Fatalf("download: %d %q", code, body)
	}
	code, body = get(t, c, ce.console.URL+"/files/zip?job="+jobID+"&path="+url.QueryEscape(filepath.Join(dir, "report.txt")))
	zr, err := zip.NewReader(strings.NewReader(body), int64(len(body)))
	if code != 200 || err != nil || len(zr.File) != 1 || !strings.HasSuffix(zr.File[0].Name, "/report.txt") {
		t.Fatalf("zip: %d %v", code, err)
	}
	// A new folder.
	code, _, _ = post(t, c, base+"/mkdir", url.Values{"csrf": {csrf}, "path": {filepath.Join(dir, "new")}})
	if info, err := os.Stat(filepath.Join(dir, "new")); code != 200 || err != nil || !info.IsDir() {
		t.Fatalf("mkdir: %d %v", code, err)
	}
	// The agent's data folder is refused.
	if code, m := getJSON(base + "/list?path=" + url.QueryEscape(cfg.DataDir)); code == 200 {
		t.Fatalf("agent folder listed: %v", m)
	}

	// Another operator cannot use the session.
	other := admin
	other.OID, other.Username = ids.NewUUID(), "luigi@cliente.it"
	oc, _ := ce.loginTo(t, other)
	if code, _ := get(t, oc, base+"/list"); code != http.StatusNotFound {
		t.Fatalf("another operator used the session: %d", code)
	}

	post(t, c, ce.console.URL+"/files/close", url.Values{"csrf": {csrf}, "job": {jobID}})
	j := e.waitFinal(t, jobID)
	if j.State != store.JobSucceeded || !strings.Contains(string(j.Result), `"uploads":1`) {
		t.Fatalf("job = %s %s %s", j.State, j.Error, j.Result)
	}
	var up, down bool
	waitFor(t, func() bool {
		events, _ := e.store.ListAudit(context.Background(), e.tenant)
		for _, ev := range events {
			up = up || ev.Action == "files.upload" && ev.Details["path"] == filepath.Join(dir, "setup.bin")
			down = down || ev.Action == "files.download" && ev.Details["path"] == filepath.Join(dir, "report.txt")
		}
		return up && down
	})
}
