package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Applications: a curated catalog maps the names in the inventory to their
// NVD product (CPE vendor:product). Only products whose installed version
// compares reliably with NVD's version ranges are listed; others would give
// false alarms. NVD is queried once a day per product.

// App is a catalog entry.
type App struct {
	Label string         // shown in reports
	CPE   string         // vendor:product, as in cpe:2.3:a:<vendor>:<product>
	Name  *regexp.Regexp // the inventory name
	// FromName takes the version from the name (first group) instead of
	// the installer's version, which some products number differently.
	FromName *regexp.Regexp
	// Winget is the package that installs the application for every user,
	// the fix for a copy installed in a user's profile.
	Winget string
}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

// Apps is the catalog.
var Apps = []App{
	{Label: "Google Chrome", CPE: "google:chrome", Name: re(`^Google Chrome$`), Winget: "Google.Chrome"},
	{Label: "Mozilla Firefox", CPE: "mozilla:firefox", Name: re(`^Mozilla Firefox(?: \(|$| \d)`), Winget: "Mozilla.Firefox"},
	{Label: "Mozilla Firefox ESR", CPE: "mozilla:firefox_esr", Name: re(`^Mozilla Firefox ESR`), Winget: "Mozilla.Firefox.ESR"},
	{Label: "Mozilla Thunderbird", CPE: "mozilla:thunderbird", Name: re(`^Mozilla Thunderbird`), Winget: "Mozilla.Thunderbird"},
	{Label: "Microsoft Edge", CPE: "microsoft:edge_chromium", Name: re(`^Microsoft Edge$`)},
	{Label: "7-Zip", CPE: "7-zip:7-zip", Name: re(`^7-Zip \d`), Winget: "7zip.7zip"},
	{Label: "Notepad++", CPE: `notepad-plus-plus:notepad\+\+`, Name: re(`^Notepad\+\+`), Winget: "Notepad++.Notepad++"},
	{Label: "VLC media player", CPE: "videolan:vlc_media_player", Name: re(`^VLC media player`), Winget: "VideoLAN.VLC"},
	{Label: "PuTTY", CPE: "simon_tatham:putty", Name: re(`^PuTTY release`), Winget: "PuTTY.PuTTY"},
	{Label: "WinRAR", CPE: "rarlab:winrar", Name: re(`^WinRAR \d`)},
	{Label: "WinSCP", CPE: "winscp:winscp", Name: re(`^WinSCP \d`), Winget: "WinSCP.WinSCP"},
	{Label: "FileZilla", CPE: "filezilla-project:filezilla_client", Name: re(`^FileZilla(?: Client)? \d`)},
	{Label: "KeePass", CPE: "dominik_reichl:keepass", Name: re(`^KeePass Password Safe 2`), Winget: "DominikReichl.KeePass"},
	{Label: "Wireshark", CPE: "wireshark:wireshark", Name: re(`^Wireshark \d`), Winget: "WiresharkFoundation.Wireshark"},
	{Label: "Git", CPE: "git-scm:git", Name: re(`^Git$|^Git version \d`), Winget: "Git.Git"},
	{Label: "Node.js", CPE: "nodejs:node.js", Name: re(`^Node\.js$`)},
	{Label: "Python", CPE: "python:python", Name: re(`^Python 3\.\d+\.\d+ \(`), FromName: re(`^Python (3\.\d+\.\d+)`)},
	{Label: "OpenVPN", CPE: "openvpn:openvpn", Name: re(`^OpenVPN \d`), FromName: re(`^OpenVPN (\d+\.\d+\.\d+)`)},
	{Label: "TeamViewer", CPE: "teamviewer:teamviewer", Name: re(`^TeamViewer(?: \d+)?$`)},
	{Label: "AnyDesk", CPE: "anydesk:anydesk", Name: re(`^AnyDesk$`)},
	{Label: "Zoom Workplace", CPE: "zoom:workplace_desktop", Name: re(`^Zoom(?: Workplace)?(?: \(64-bit\))?$`), Winget: "Zoom.Zoom"},
	{Label: "Adobe Acrobat Reader", CPE: "adobe:acrobat_reader_dc", Name: re(`^Adobe Acrobat Reader`), Winget: "Adobe.Acrobat.Reader.64-bit"},
	{Label: "Adobe Acrobat", CPE: "adobe:acrobat_dc", Name: re(`^Adobe Acrobat(?: DC)?(?: \(64-bit\))?$`)},
	{Label: "Foxit PDF Reader", CPE: "foxit:pdf_reader", Name: re(`^Foxit (?:PDF )?Reader`)},
	{Label: "LibreOffice", CPE: "libreoffice:libreoffice", Name: re(`^LibreOffice \d`), Winget: "TheDocumentFoundation.LibreOffice"},
	{Label: "Citrix Workspace", CPE: "citrix:workspace", Name: re(`^Citrix Workspace`)},
	{Label: "VMware Tools", CPE: "vmware:tools", Name: re(`^VMware Tools$`)},
}

// AppCVE is a CVE of an application with the vulnerable versions.
type AppCVE struct {
	ID       string     `json:"id"`
	Title    string     `json:"title,omitempty"`
	CVSS     float64    `json:"cvss,omitempty"`
	Released time.Time  `json:"released,omitempty"`
	Ranges   []VerRange `json:"ranges"`
}

// VerRange is a vulnerable version range; an empty bound is open. Exact
// holds a single version.
type VerRange struct {
	Exact     string `json:"exact,omitempty"`
	StartIncl string `json:"si,omitempty"`
	StartExcl string `json:"se,omitempty"`
	EndIncl   string `json:"ei,omitempty"`
	EndExcl   string `json:"ee,omitempty"`
}

// Contains tells whether version v is in the range.
func (r VerRange) Contains(v string) bool {
	if r.Exact != "" {
		return CompareVersions(v, r.Exact) == 0
	}
	if r.StartIncl == "" && r.StartExcl == "" && r.EndIncl == "" && r.EndExcl == "" {
		return false // "every version": too vague to report
	}
	if r.StartIncl != "" && CompareVersions(v, r.StartIncl) < 0 {
		return false
	}
	if r.StartExcl != "" && CompareVersions(v, r.StartExcl) <= 0 {
		return false
	}
	if r.EndIncl != "" && CompareVersions(v, r.EndIncl) > 0 {
		return false
	}
	if r.EndExcl != "" && CompareVersions(v, r.EndExcl) >= 0 {
		return false
	}
	return true
}

// Fix is the version to update to, when the range says it.
func (r VerRange) Fix() string {
	if r.EndExcl != "" {
		return r.EndExcl
	}
	return ""
}

var verPart = regexp.MustCompile(`\d+|[A-Za-z]+`)

// CompareVersions compares dotted versions numerically: 23.01 < 24.07,
// 0.81.0.0 = 0.81, 130.0.6723.117 > 130.0.6723.58.
func CompareVersions(a, b string) int {
	pa, pb := verPart.FindAllString(a, -1), verPart.FindAllString(b, -1)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		x, y := "0", "0"
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if nx != ny {
				if nx < ny {
					return -1
				}
				return 1
			}
		case ex == nil: // number after a letter: 1.0 > 1.0beta
			return 1
		case ey == nil:
			return -1
		default:
			if c := strings.Compare(strings.ToLower(x), strings.ToLower(y)); c != 0 {
				return c
			}
		}
	}
	return 0
}

type nvdPage struct {
	TotalResults    int `json:"totalResults"`
	ResultsPerPage  int `json:"resultsPerPage"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			VulnStatus   string `json:"vulnStatus"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics map[string][]struct {
				CVSSData struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Vulnerable bool   `json:"vulnerable"`
						Criteria   string `json:"criteria"`
						SI         string `json:"versionStartIncluding"`
						SE         string `json:"versionStartExcluding"`
						EI         string `json:"versionEndIncluding"`
						EE         string `json:"versionEndExcluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// parseNVD extracts the CVEs of product cpe (vendor:product).
func parseNVD(p *nvdPage, cpe string) []AppCVE {
	prefix := "cpe:2.3:a:" + cpe + ":"
	var out []AppCVE
	for _, v := range p.Vulnerabilities {
		c := v.CVE
		if c.VulnStatus == "Rejected" {
			continue
		}
		ac := AppCVE{ID: c.ID}
		if t, err := time.Parse("2006-01-02T15:04:05.000", c.Published); err == nil {
			ac.Released = t
		}
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				ac.Title = d.Value
				if len(ac.Title) > 200 {
					ac.Title = ac.Title[:197] + "…"
				}
				break
			}
		}
		for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			for _, m := range c.Metrics[k] {
				ac.CVSS = max(ac.CVSS, m.CVSSData.BaseScore)
			}
			if ac.CVSS > 0 {
				break
			}
		}
		for _, cf := range c.Configurations {
			for _, n := range cf.Nodes {
				for _, m := range n.CPEMatch {
					if !m.Vulnerable || !strings.HasPrefix(m.Criteria, prefix) {
						continue
					}
					r := VerRange{StartIncl: m.SI, StartExcl: m.SE, EndIncl: m.EI, EndExcl: m.EE}
					if ver := strings.SplitN(strings.TrimPrefix(m.Criteria, prefix), ":", 2)[0]; ver != "*" && ver != "-" && ver != "" {
						r = VerRange{Exact: strings.ReplaceAll(ver, `\`, "")}
					}
					ac.Ranges = append(ac.Ranges, r)
				}
			}
		}
		if len(ac.Ranges) > 0 {
			out = append(out, ac)
		}
	}
	return out
}

// refreshNVD downloads the CVEs of every catalog product once a day.
func (f *Fetcher) refreshNVD(ctx context.Context) error {
	var first error
	for _, app := range Apps {
		fk := "nvd/" + app.CPE
		if f.fresh(ctx, fk, 24*time.Hour) {
			continue
		}
		var all []AppCVE
		for start := 0; ; {
			q := url.Values{"virtualMatchString": {"cpe:2.3:a:" + app.CPE}, "startIndex": {strconv.Itoa(start)}, "resultsPerPage": {"2000"}}
			var page nvdPage
			err := f.getWith(ctx, f.NVD+"?"+q.Encode(), map[string]string{"apiKey": f.NVDKey}, &page)
			if err == nil {
				all = append(all, parseNVD(&page, app.CPE)...)
				start += page.ResultsPerPage
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(f.NVDPause):
			}
			if err != nil {
				if first == nil {
					first = fmt.Errorf("%s: %w", app.Label, err)
				}
				all = nil
				break
			}
			if page.ResultsPerPage == 0 || start >= page.TotalResults {
				break
			}
		}
		if all == nil && first != nil {
			continue
		}
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		if err := f.put(ctx, fk, "", all); err != nil {
			return err
		}
		f.Log.Info("NVD application CVEs downloaded", "product", app.Label, "cves", len(all))
	}
	return first
}

// appCVEs loads the stored products.
func appCVEs(ctx context.Context, st Store) (map[string][]AppCVE, error) {
	feeds, err := st.ListVulnFeeds(ctx, "nvd/")
	if err != nil {
		return nil, err
	}
	out := map[string][]AppCVE{}
	for _, fd := range feeds {
		var list []AppCVE
		if json.Unmarshal(fd.Data, &list) == nil {
			out[strings.TrimPrefix(fd.Key, "nvd/")] = list
		}
	}
	return out, nil
}

// InstalledApp is an application of the inventory.
type InstalledApp struct {
	Name, Version string
	UserScope     bool // installed in a user's profile
}

// appVersion returns the catalog entry and the version of an installed
// application, or false when it is not in the catalog.
func appVersion(a InstalledApp) (*App, string, bool) {
	for i := range Apps {
		app := &Apps[i]
		if !app.Name.MatchString(a.Name) {
			continue
		}
		v := strings.TrimSpace(a.Version)
		if app.FromName != nil {
			if m := app.FromName.FindStringSubmatch(a.Name); m != nil {
				v = m[1]
			}
		}
		// "6.2.5 (47302)": the leading version.
		if m := leadingVersion.FindString(v); m != "" {
			v = m
		}
		return app, v, v != ""
	}
	return nil, "", false
}

var leadingVersion = regexp.MustCompile(`^\d+(?:\.\d+)*`)

// AppByLabel returns the catalog entry shown as label, or nil.
func AppByLabel(label string) *App {
	for i := range Apps {
		if Apps[i].Label == label {
			return &Apps[i]
		}
	}
	return nil
}
