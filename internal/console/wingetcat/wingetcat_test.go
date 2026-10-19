package wingetcat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stefanozanarini/open-rmm/internal/console/pkgfiles"
)

var payload = []byte("fake msi bytes")

func fakeRepo(t *testing.T, sha string) (*Client, *httptest.Server) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/microsoft/winget-pkgs/contents/manifests/7/7zip/7zip":
			w.Write([]byte(`[{"name":"23.01","type":"dir"},{"name":"24.08","type":"dir"},{"name":"9.20","type":"dir"},{"name":"Alpha","type":"dir"},{"name":"README.md","type":"file"}]`))
		case "/microsoft/winget-pkgs/master/manifests/7/7zip/7zip/24.08/7zip.7zip.installer.yaml":
			w.Write([]byte(`PackageIdentifier: 7zip.7zip
PackageVersion: "24.08"
InstallerType: exe
InstallerSwitches:
  Silent: /S
Installers:
- Architecture: x86
  Scope: user
  InstallerUrl: https://example.invalid/7z2408.exe
  InstallerSha256: ` + strings.Repeat("a", 64) + `
- Architecture: arm64
  InstallerType: msi
  InstallerUrl: https://example.invalid/7z2408-arm64.msi
  InstallerSha256: ` + strings.Repeat("b", 64) + `
- Architecture: x64
  InstallerType: wix
  Scope: machine
  InstallerUrl: ` + srv.URL + `/files/7z2408-x64.msi
  InstallerSha256: ` + strings.ToUpper(sha) + `
  ProductCode: '{23170F69-40C1-2702-2408-000001000000}'
  AppsAndFeaturesEntries:
  - DisplayName: 7-Zip 24.08 (x64 edition)
    DisplayVersion: 24.08.00.0
- Architecture: x64
  InstallerUrl: http://insecure.invalid/7z.exe
  InstallerSha256: ` + strings.Repeat("c", 64) + `
ManifestType: installer
`))
		case "/microsoft/winget-pkgs/master/manifests/7/7zip/7zip/24.08/7zip.7zip.yaml":
			w.Write([]byte("PackageIdentifier: 7zip.7zip\nDefaultLocale: en-US\n"))
		case "/microsoft/winget-pkgs/master/manifests/7/7zip/7zip/24.08/7zip.7zip.locale.en-US.yaml":
			w.Write([]byte("Publisher: Igor Pavlov\nPackageName: 7-Zip\n"))
		case "/files/7z2408-x64.msi":
			w.Write(payload)
		case "/files/redirect":
			http.Redirect(w, r, "http://insecure.invalid/x.msi", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.HTTP = srv.Client()
	c.HTTP.CheckRedirect = httpsOnly
	c.APIBase, c.RawBase = srv.URL, srv.URL
	return c, srv
}

func TestLatestAndDownload(t *testing.T) {
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	c, srv := fakeRepo(t, sha)
	ctx := context.Background()
	rel, err := c.Latest(ctx, "7zip.7zip")
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "24.08" || rel.Kind != "msi" || rel.SHA256 != sha || rel.Name != "7-Zip" || rel.Publisher != "Igor Pavlov" ||
		rel.MatchName != "7-Zip" || rel.DisplayVersion != "24.08.00.0" || rel.FileName != "7z2408-x64.msi" ||
		len(rel.ProductCodes) == 0 || rel.ProductCodes[0] != "{23170F69-40C1-2702-2408-000001000000}" {
		t.Fatalf("release = %+v", rel)
	}
	dir := pkgfiles.Dir{Path: t.TempDir()}
	if n, err := c.Download(ctx, rel, dir, 1<<20); err != nil || n != int64(len(payload)) {
		t.Fatal(n, err)
	}
	if f, err := dir.Open(sha); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	bad := *rel
	bad.SHA256 = strings.Repeat("0", 64)
	if _, err := c.Download(ctx, &bad, pkgfiles.Dir{Path: t.TempDir()}, 1<<20); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("hash mismatch: %v", err)
	}
	redir := *rel
	redir.URL = srv.URL + "/files/redirect"
	if _, err := c.Download(ctx, &redir, dir, 1<<20); err == nil {
		t.Fatal("redirect to HTTP followed")
	}
	if _, err := c.Latest(ctx, "Nope.Nothing"); err != ErrNotFound {
		t.Fatalf("unknown package: %v", err)
	}
	if _, err := c.Latest(ctx, "../../etc"); err == nil {
		t.Fatal("invalid id accepted")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"24.08", "23.01", 1}, {"9.20", "24.08", -1}, {"131.0.2", "131.0.10", -1}, {"1.0", "1.0.0", 0},
		{"24.08.00.0", "24.08", 0}, {"2.0-beta", "2.0", 1}, {"v1.2", "1.2", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d", c.a, c.b, got)
		}
	}
}

func TestMatchName(t *testing.T) {
	for in, want := range map[string]string{"7-Zip 24.08 (x64 edition)": "7-Zip", "Mozilla Firefox (x64 it)": "Mozilla Firefox",
		"Notepad++ (64-bit x64)": "Notepad++", "Google Chrome": "Google Chrome", "VLC media player v3.0": "VLC media player"} {
		if got := MatchName(in); got != want {
			t.Errorf("%q -> %q", in, got)
		}
	}
}
