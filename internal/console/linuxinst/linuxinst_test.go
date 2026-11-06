package linuxinst

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stefanozanarini/open-rmm/internal/agent/config"
)

func TestBuild(t *testing.T) {
	var out bytes.Buffer
	err := Build(&out, "1.0.3", "linux/amd64", []byte("AGENT"), []byte("WATCHDOG"), Settings{Server: "agent.example.com:443",
		RootCA: "MIIBroot", EnrollToken: "secret", JobKeys: "ed25519:a", ModuleKeys: "ed25519:b;ed25519:c", ReleaseKeys: "ed25519:d"})
	if err != nil {
		t.Fatal(err)
	}
	script, payload, ok := bytes.Cut(out.Bytes(), []byte("\n__PAYLOAD__\n"))
	if !ok || !strings.HasPrefix(string(script), "#!/bin/sh") || !strings.Contains(string(script), "VERSION=1.0.3") ||
		!strings.Contains(string(script), `!= x86_64`) {
		t.Fatalf("script: %s", script)
	}
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	modes := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		files[h.Name], _ = io.ReadAll(tr)
		modes[h.Name] = h.Mode
	}
	if string(files["openrmm-agent"]) != "AGENT" || modes["agent.json"] != 0o600 || files["units/openrmm-agent.service"] == nil ||
		files["units/openrmm-healthcheck.timer"] == nil {
		t.Fatalf("payload: %v", modes)
	}
	var c config.Config
	if err := json.Unmarshal(files["agent.json"], &c); err != nil || c.Server != "agent.example.com:443" || c.EnrollToken != "secret" ||
		len(c.ModuleSigningKeys) != 2 || c.RootCAPEM != "MIIBroot" {
		t.Fatalf("config: %+v %v", c, err)
	}
	if err := Build(io.Discard, "1.0.3", "windows/amd64", nil, nil, Settings{}); err == nil {
		t.Fatal("windows accepted")
	}
	if err := Build(io.Discard, "1.0.3; rm", "linux/amd64", nil, nil, Settings{}); err == nil {
		t.Fatal("invalid version accepted")
	}
}
