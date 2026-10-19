// Package wingetcat reads application manifests from the winget community
// repository (microsoft/winget-pkgs) so the console can detect outdated
// software from the inventory and distribute installers itself, also to
// endpoints without winget (e.g. Windows Server 2019).
//
// Installers are downloaded by the console, over HTTPS only, and accepted
// only if their SHA-256 matches the manifest.
package wingetcat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/stefanozanarini/open-rmm/internal/console/pkgfiles"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/pkgref"
)

const maxManifest = 1 << 20

// IDRe matches winget package identifiers.
var IDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9_+-]*){1,4}$`)

// Client reads the repository.
type Client struct {
	HTTP    *http.Client
	APIBase string // https://api.github.com
	RawBase string // https://raw.githubusercontent.com
	Repo    string // microsoft/winget-pkgs
	Branch  string // master
}

// New returns a client for the public repository.
func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 60 * time.Second, CheckRedirect: httpsOnly},
		APIBase: "https://api.github.com", RawBase: "https://raw.githubusercontent.com",
		Repo: "microsoft/winget-pkgs", Branch: "master"}
}

func httpsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errors.New("redirect to a non-HTTPS URL refused")
	}
	if len(via) > 10 {
		return errors.New("too many redirects")
	}
	return nil
}

func manifestDir(id string) string {
	return "manifests/" + strings.ToLower(id[:1]) + "/" + strings.ReplaceAll(id, ".", "/")
}

func (c *Client) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "open-rmm")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: response too large", u)
	}
	return b, nil
}

// ErrNotFound is returned for an unknown package.
var ErrNotFound = errors.New("package not found in the winget repository")

// Versions lists the published versions of a package, newest first.
func (c *Client) Versions(ctx context.Context, id string) ([]string, error) {
	if !IDRe.MatchString(id) {
		return nil, fmt.Errorf("invalid winget id %q", id)
	}
	b, err := c.get(ctx, fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", c.APIBase, c.Repo, manifestDir(id), url.QueryEscape(c.Branch)), 4<<20)
	if err != nil {
		return nil, err
	}
	var entries []struct{ Name, Type string }
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("winget repository listing: %w", err)
	}
	var out []string
	for _, e := range entries {
		// Version directories start with a digit; others are sub-packages.
		if e.Type == "dir" && e.Name != "" && e.Name[0] >= '0' && e.Name[0] <= '9' {
			out = append(out, e.Name)
		}
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	sort.Slice(out, func(i, j int) bool { return CompareVersions(out[i], out[j]) > 0 })
	return out, nil
}

// CompareVersions compares dotted versions part by part, numerically when
// both parts are numbers.
func CompareVersions(a, b string) int {
	split := func(s string) []string {
		return strings.FieldsFunc(strings.TrimPrefix(strings.ToLower(s), "v"), func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '_' || r == ' ' })
	}
	pa, pb := split(a), split(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case x == y:
			continue
		case ex == nil && ey == nil:
			if nx < ny {
				return -1
			}
			return 1
		case x == "":
			if ey == nil && ny == 0 {
				continue
			}
			return -1
		case y == "":
			if ex == nil && nx == 0 {
				continue
			}
			return 1
		case x < y:
			return -1
		default:
			return 1
		}
	}
	return 0
}

// Switches are the installer switches of a manifest.
type Switches struct {
	Silent string `yaml:"Silent"`
	Custom string `yaml:"Custom"`
}

// ARPEntry is an "Apps and Features" entry of a manifest.
type ARPEntry struct {
	DisplayName    string `yaml:"DisplayName"`
	Publisher      string `yaml:"Publisher"`
	DisplayVersion string `yaml:"DisplayVersion"`
	ProductCode    string `yaml:"ProductCode"`
}

type installer struct {
	Architecture           string     `yaml:"Architecture"`
	InstallerType          string     `yaml:"InstallerType"`
	Scope                  string     `yaml:"Scope"`
	InstallerLocale        string     `yaml:"InstallerLocale"`
	InstallerURL           string     `yaml:"InstallerUrl"`
	InstallerSha256        string     `yaml:"InstallerSha256"`
	ProductCode            string     `yaml:"ProductCode"`
	InstallerSwitches      *Switches  `yaml:"InstallerSwitches"`
	AppsAndFeaturesEntries []ARPEntry `yaml:"AppsAndFeaturesEntries"`
}

type installerManifest struct {
	installer  `yaml:",inline"`
	Installers []installer `yaml:"Installers"`
}

type versionManifest struct {
	DefaultLocale string `yaml:"DefaultLocale"`
}

type localeManifest struct {
	Publisher   string `yaml:"Publisher"`
	PackageName string `yaml:"PackageName"`
}

// Release is the installer chosen for an endpoint fleet: machine scope,
// x64 when available, a kind the software module can run silently.
type Release struct {
	ID          string
	Version     string
	Name        string
	Publisher   string
	URL         string
	SHA256      string // hex, lowercase
	Kind        string // msi | exe | inno | nullsoft | burn
	SilentArgs  string // for exe kinds; MSI properties for msi
	ProductCode string
	FileName    string
	// MatchName is the display-name prefix that identifies the application
	// in the inventory; DisplayVersion is the version it shows there.
	MatchName      string
	DisplayVersion string
	ProductCodes   []string
}

var kinds = map[string]string{"msi": "msi", "wix": "msi", "inno": "inno", "nullsoft": "nullsoft", "burn": "burn", "exe": "exe"}

var shaRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func (c *Client) raw(ctx context.Context, p string) ([]byte, error) {
	return c.get(ctx, fmt.Sprintf("%s/%s/%s/%s", c.RawBase, c.Repo, c.Branch, p), maxManifest)
}

// Latest returns the installer of the newest version.
func (c *Client) Latest(ctx context.Context, id string) (*Release, error) {
	versions, err := c.Versions(ctx, id)
	if err != nil {
		return nil, err
	}
	return c.Release(ctx, id, versions[0])
}

// Release reads the manifests of one version and chooses its installer.
func (c *Client) Release(ctx context.Context, id, version string) (*Release, error) {
	dir := manifestDir(id) + "/" + version
	b, err := c.raw(ctx, dir+"/"+id+".installer.yaml")
	if err != nil {
		return nil, err
	}
	var im installerManifest
	if err := yaml.Unmarshal(b, &im); err != nil {
		return nil, fmt.Errorf("installer manifest: %w", err)
	}
	rel := &Release{ID: id, Version: version}
	var vm versionManifest
	if vb, err := c.raw(ctx, dir+"/"+id+".yaml"); err == nil && yaml.Unmarshal(vb, &vm) == nil && vm.DefaultLocale != "" {
		var lm localeManifest
		if lb, err := c.raw(ctx, dir+"/"+id+".locale."+vm.DefaultLocale+".yaml"); err == nil && yaml.Unmarshal(lb, &lm) == nil {
			rel.Name, rel.Publisher = lm.PackageName, lm.Publisher
		}
	}
	if rel.Name == "" {
		rel.Name = id
	}
	if err := choose(&im, rel); err != nil {
		return nil, err
	}
	return rel, nil
}

func merge(root, in installer) installer {
	if in.InstallerType == "" {
		in.InstallerType = root.InstallerType
	}
	if in.Scope == "" {
		in.Scope = root.Scope
	}
	if in.InstallerSwitches == nil {
		in.InstallerSwitches = root.InstallerSwitches
	}
	if in.ProductCode == "" {
		in.ProductCode = root.ProductCode
	}
	if len(in.AppsAndFeaturesEntries) == 0 {
		in.AppsAndFeaturesEntries = root.AppsAndFeaturesEntries
	}
	if in.InstallerLocale == "" {
		in.InstallerLocale = root.InstallerLocale
	}
	return in
}

func score(in installer) int {
	s := 0
	switch strings.ToLower(in.Architecture) {
	case "x64":
		s += 40
	case "neutral":
		s += 30
	case "x86":
		s += 20
	}
	switch strings.ToLower(in.Scope) {
	case "machine":
		s += 10
	case "":
		s += 5
	}
	switch strings.ToLower(in.InstallerType) {
	case "msi", "wix":
		s += 3
	}
	switch strings.ToLower(in.InstallerLocale) {
	case "", "en-us", "it-it":
		s += 1
	}
	return s
}

func choose(im *installerManifest, rel *Release) error {
	var best *installer
	bestScore := -1
	for _, raw := range im.Installers {
		in := merge(im.installer, raw)
		if _, ok := kinds[strings.ToLower(in.InstallerType)]; !ok || strings.EqualFold(in.Scope, "user") {
			continue
		}
		if a := strings.ToLower(in.Architecture); a != "x64" && a != "x86" && a != "neutral" {
			continue
		}
		u, err := url.Parse(in.InstallerURL)
		if err != nil || u.Scheme != "https" || !shaRe.MatchString(in.InstallerSha256) {
			continue
		}
		if sc := score(in); sc > bestScore {
			in := in
			best, bestScore = &in, sc
		}
	}
	if best == nil {
		return errors.New("no machine-wide x64/x86 installer of a supported type (msi, exe, inno, nullsoft, burn) over HTTPS")
	}
	rel.URL, rel.SHA256 = best.InstallerURL, strings.ToLower(best.InstallerSha256)
	rel.Kind = kinds[strings.ToLower(best.InstallerType)]
	rel.ProductCode = best.ProductCode
	if sw := best.InstallerSwitches; sw != nil {
		if rel.Kind == "exe" {
			rel.SilentArgs = strings.TrimSpace(sw.Silent + " " + sw.Custom)
		} else {
			rel.SilentArgs = strings.TrimSpace(sw.Custom)
		}
	}
	if rel.Kind == "exe" && rel.SilentArgs == "" {
		return errors.New("the manifest gives no silent switches for this installer")
	}
	for _, e := range best.AppsAndFeaturesEntries {
		if e.ProductCode != "" {
			rel.ProductCodes = append(rel.ProductCodes, strings.ToUpper(e.ProductCode))
		}
		if rel.MatchName == "" && e.DisplayName != "" {
			rel.MatchName = MatchName(e.DisplayName)
		}
		if rel.DisplayVersion == "" {
			rel.DisplayVersion = e.DisplayVersion
		}
	}
	if best.ProductCode != "" {
		rel.ProductCodes = append(rel.ProductCodes, strings.ToUpper(best.ProductCode))
	}
	if rel.MatchName == "" {
		rel.MatchName = MatchName(rel.Name)
	}
	if rel.DisplayVersion == "" {
		rel.DisplayVersion = rel.Version
	}
	rel.FileName = fileName(rel)
	return nil
}

// MatchName drops what follows the first word starting with a digit or a
// parenthesis ("7-Zip 24.08 (x64)" -> "7-Zip").
func MatchName(display string) string {
	var keep []string
	for i, w := range strings.Fields(display) {
		// The first word is always kept (e.g. "7-Zip").
		if c := w[0]; i > 0 && ((c >= '0' && c <= '9') || c == '(' || c == 'v' && len(w) > 1 && w[1] >= '0' && w[1] <= '9') {
			break
		}
		keep = append(keep, w)
	}
	if len(keep) == 0 {
		return strings.TrimSpace(display)
	}
	return strings.Join(keep, " ")
}

func fileName(rel *Release) string {
	ext := ".exe"
	if rel.Kind == "msi" {
		ext = ".msi"
	}
	u, _ := url.Parse(rel.URL)
	base := path.Base(u.Path)
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, base)
	if !strings.HasSuffix(strings.ToLower(clean), ext) {
		clean = strings.TrimSuffix(clean, path.Ext(clean)) + ext
	}
	if !pkgref.ValidFileName(clean) || len(clean) > 100 {
		clean = strings.ReplaceAll(rel.ID+"-"+rel.Version, "+", "_") + ext
	}
	return clean
}

// Download fetches the installer into the package store and checks its
// SHA-256 against the manifest.
func (c *Client) Download(ctx context.Context, rel *Release, dir pkgfiles.Dir, maxSize int64) (int64, error) {
	u, err := url.Parse(rel.URL)
	if err != nil || u.Scheme != "https" {
		return 0, errors.New("installer URL must be HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "open-rmm")
	hc := *c.HTTP
	hc.Timeout = 0 // large files: bounded by ctx
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download: %s", resp.Status)
	}
	sum, n, err := dir.Save(resp.Body, maxSize)
	if err != nil {
		return 0, err
	}
	if sum != rel.SHA256 {
		_ = dir.Remove(sum)
		return 0, fmt.Errorf("downloaded file SHA-256 %s does not match the manifest (%s)", sum, rel.SHA256)
	}
	return n, nil
}

// Installed finds an application of the catalog in an inventory software
// list, by product code first and then by display-name prefix, and returns
// the installed versions (several when installed more than once).
func Installed(software []inventory.Software, matchName string, productCodes []string) []string {
	codes := map[string]bool{}
	for _, c := range productCodes {
		codes[strings.ToUpper(c)] = true
	}
	prefix := strings.ToLower(strings.TrimSpace(matchName))
	var out []string
	for _, s := range software {
		name := strings.ToLower(s.Name)
		switch {
		case s.ProductCode != "" && codes[strings.ToUpper(s.ProductCode)]:
		case prefix != "" && (name == prefix || strings.HasPrefix(name, prefix+" ")):
		default:
			continue
		}
		out = append(out, s.Version)
	}
	return out
}
