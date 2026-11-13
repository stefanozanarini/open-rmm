package web

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

// Software inventory: the applications of every computer's last inventory,
// grouped by publisher, title or version, or listed one installation per
// row. Each level links to the next one with exact filters (pub, title,
// ver); q searches the text contained.

const (
	maxSoftwareRows   = 1000
	maxSoftwareCharts = 6
)

type swData struct {
	View                      string // publishers | titles | versions | installs
	Query                     string
	Publisher, Title, Version string
	HasPub, HasTitle, HasVer  bool
	All                       bool // also system components and updates
	Sort                      string
	Charts                    []vbarChart
	Rows                      []swRow
	Installs                  []swInstall
	Total                     int // rows before the limit
	Computers                 int // computers with an inventory
	CSV                       string
}

type swRow struct {
	Publisher, Title, Version string
	Titles, Versions          int
	Computers, Users          int
	Link, InstallsLink        string
}

type swInstall struct {
	AgentID, Hostname, User   string
	Publisher, Title, Version string
	Arch, Scope, InstallDate  string
}

// swGroup collects the computers and users of a publisher, title or version.
type swGroup struct {
	row       swRow
	computers map[string]bool
	users     map[string]bool
	titles    map[string]bool
	versions  map[string]bool
}

func (g *swGroup) add(agentID, user, title, version string) {
	g.computers[agentID] = true
	if user != "" {
		g.users[strings.ToLower(user)] = true
	}
	g.titles[title] = true
	g.versions[title+"\x00"+version] = true
}

func newGroup(r swRow) *swGroup {
	return &swGroup{row: r, computers: map[string]bool{}, users: map[string]bool{}, titles: map[string]bool{}, versions: map[string]bool{}}
}

// link is a software inventory URL with the given view and filters; the
// publisher filter is kept even when empty (applications without one).
func (d *swData) link(view string, pub, title, ver *string) string {
	v := url.Values{"tab": {"software"}, "view": {view}}
	if pub != nil {
		v.Set("pub", *pub)
	}
	if title != nil {
		v.Set("title", *title)
	}
	if ver != nil {
		v.Set("ver", *ver)
	}
	if d.All {
		v.Set("all", "1")
	}
	return "/reports?" + v.Encode()
}

// filters returns the current filters, for links that keep them.
func (d *swData) filters() url.Values {
	v := url.Values{"tab": {"software"}, "view": {d.View}}
	if d.HasPub {
		v.Set("pub", d.Publisher)
	}
	if d.HasTitle {
		v.Set("title", d.Title)
	}
	if d.HasVer {
		v.Set("ver", d.Version)
	}
	if d.Query != "" {
		v.Set("q", d.Query)
	}
	if d.All {
		v.Set("all", "1")
	}
	return v
}

// ViewURL switches view keeping the filters.
func (d *swData) ViewURL(view string) string {
	v := d.filters()
	v.Set("view", view)
	return "/reports?" + v.Encode()
}

// SortURL is the link of a column header: descending first, then ascending.
func (d *swData) SortURL(col string) string {
	v := d.filters()
	v.Set("sort", col)
	if d.Sort == col {
		v.Set("sort", col+"_asc")
	}
	return "/reports?" + v.Encode()
}

// SortMark is the arrow of a column header.
func (d *swData) SortMark(col string) string {
	switch d.Sort {
	case col:
		return " ▼"
	case col + "_asc":
		return " ▲"
	}
	return ""
}

// ClearURL drops one filter.
func (d *swData) ClearURL(key string) string {
	v := d.filters()
	v.Del(key)
	return "/reports?" + v.Encode()
}

// Filtered tells whether an exact filter is set.
func (d *swData) Filtered() bool { return d.HasPub || d.HasTitle || d.HasVer }

func (s *Server) softwareInventory(w http.ResponseWriter, r *http.Request, t string) (*swData, bool) {
	q := r.URL.Query()
	d := &swData{View: q.Get("view"), Query: strings.TrimSpace(q.Get("q")), Sort: q.Get("sort"), All: q.Get("all") == "1",
		Publisher: q.Get("pub"), Title: q.Get("title"), Version: q.Get("ver"),
		HasPub: q.Has("pub"), HasTitle: q.Has("title"), HasVer: q.Has("ver")}
	switch d.View {
	case "publishers", "versions", "installs":
	default:
		d.View = "titles"
	}
	csvOut := q.Get("format") == "csv"
	v := d.filters()
	if d.Sort != "" {
		v.Set("sort", d.Sort)
	}
	v.Set("format", "csv")
	d.CSV = "/reports?" + v.Encode()

	ctx := r.Context()
	agents, err := s.store.ListAgents(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	invs, err := s.store.ListInventories(ctx, t)
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	byAgent := map[string]store.Inventory{}
	for _, i := range invs {
		byAgent[i.AgentID] = i
	}
	lastUsers, ttl := s.lastUsers(ctx, t)

	pubs, titles, versions := map[string]*swGroup{}, map[string]*swGroup{}, map[string]*swGroup{}
	group := func(m map[string]*swGroup, key string, r swRow) *swGroup {
		g, ok := m[key]
		if !ok {
			g = newGroup(r)
			m[key] = g
		}
		return g
	}
	for _, a := range agents {
		if a.Status == store.AgentRevoked {
			continue
		}
		stored, ok := byAgent[a.ID]
		if !ok {
			continue
		}
		inv, err := inventory.Parse(stored.Data)
		if err != nil {
			continue
		}
		d.Computers++
		lu, hasLU := lastUsers[a.ID]
		user := s.userFor(a, stored.Summary, lu, hasLU, ttl).Name
		apps := inv.VisibleSoftware()
		if d.All {
			apps = inv.Software
		}
		for _, sw := range apps {
			pub, title, ver := strings.TrimSpace(sw.Publisher), strings.TrimSpace(sw.Name), strings.TrimSpace(sw.Version)
			if title == "" || (d.HasPub && pub != d.Publisher) || (d.HasTitle && title != d.Title) || (d.HasVer && ver != d.Version) {
				continue
			}
			if d.Query != "" && !contains(pub, d.Query) && !contains(title, d.Query) && !contains(ver, d.Query) &&
				(d.View != "installs" || (!contains(a.Host.Hostname, d.Query) && !contains(user, d.Query))) {
				continue
			}
			group(pubs, pub, swRow{Publisher: pub}).add(a.ID, user, title, ver)
			group(titles, pub+"\x00"+title, swRow{Publisher: pub, Title: title}).add(a.ID, user, title, ver)
			group(versions, pub+"\x00"+title+"\x00"+ver, swRow{Publisher: pub, Title: title, Version: ver}).add(a.ID, user, title, ver)
			if d.View == "installs" {
				d.Installs = append(d.Installs, swInstall{AgentID: a.ID, Hostname: a.Host.Hostname, User: user, Publisher: pub,
					Title: title, Version: ver, Arch: sw.Arch, Scope: sw.Scope, InstallDate: sw.InstallDate})
			}
		}
	}

	rows := func(m map[string]*swGroup, level string) []swRow {
		out := make([]swRow, 0, len(m))
		for _, g := range m {
			r := g.row
			r.Computers, r.Users, r.Titles, r.Versions = len(g.computers), len(g.users), len(g.titles), len(g.versions)
			pub, title, ver := r.Publisher, r.Title, r.Version
			switch level {
			case "versions":
				r.Link = d.link("installs", &pub, &title, &ver)
				r.InstallsLink = r.Link
			case "titles":
				r.Link, r.InstallsLink = d.link("versions", &pub, &title, nil), d.link("installs", &pub, &title, nil)
			default:
				r.Link, r.InstallsLink = d.link("titles", &pub, nil, nil), d.link("installs", &pub, nil, nil)
			}
			out = append(out, r)
		}
		return out
	}
	pubRows, titleRows, verRows := rows(pubs, "publishers"), rows(titles, "titles"), rows(versions, "versions")
	byComputers := func(rs []swRow) {
		sort.SliceStable(rs, func(i, j int) bool {
			if rs[i].Computers != rs[j].Computers {
				return rs[i].Computers > rs[j].Computers
			}
			return swLess(rs[i], rs[j])
		})
	}
	byComputers(pubRows)
	byComputers(titleRows)
	byComputers(verRows)

	// Charts: where the applications come from and the most installed ones,
	// narrowed to the versions once a title is chosen.
	switch {
	case d.HasTitle:
		d.Charts = append(d.Charts, newVBars(s.T(r, "Versioni più installate"), s.T(r, "computer per versione"), verRows,
			func(r swRow) string { return r.Version }))
	case d.HasPub:
		d.Charts = append(d.Charts, newVBars(s.T(r, "Applicazioni più installate"), s.T(r, "computer per applicazione"), titleRows,
			func(r swRow) string { return r.Title }))
	default:
		d.Charts = append(d.Charts,
			newVBars(s.T(r, "Produttori più diffusi"), s.T(r, "computer con almeno un'applicazione del produttore"), pubRows,
				func(r swRow) string { return r.Publisher }),
			newVBars(s.T(r, "Applicazioni più installate"), s.T(r, "computer per applicazione"), titleRows,
				func(r swRow) string { return r.Title }))
	}

	switch d.View {
	case "publishers":
		d.Rows = pubRows
	case "titles":
		d.Rows = titleRows
	case "versions":
		d.Rows = verRows
	}
	sortSoftware(d.Rows, d.Sort)
	sortInstalls(d.Installs, d.Sort)
	if csvOut {
		s.softwareCSV(w, d)
		return nil, false
	}
	d.Total = len(d.Rows) + len(d.Installs)
	if len(d.Rows) > maxSoftwareRows {
		d.Rows = d.Rows[:maxSoftwareRows]
	}
	if len(d.Installs) > maxSoftwareRows {
		d.Installs = d.Installs[:maxSoftwareRows]
	}
	return d, true
}

func swLess(a, b swRow) bool {
	if x, y := strings.ToLower(a.Publisher), strings.ToLower(b.Publisher); x != y {
		return x < y
	}
	if x, y := strings.ToLower(a.Title), strings.ToLower(b.Title); x != y {
		return x < y
	}
	return a.Version < b.Version
}

func sortSoftware(rs []swRow, by string) {
	key := func(r swRow) int {
		switch strings.TrimSuffix(by, "_asc") {
		case "users":
			return r.Users
		case "titles":
			return r.Titles
		case "versions":
			return r.Versions
		}
		return r.Computers
	}
	asc := strings.HasSuffix(by, "_asc")
	sort.SliceStable(rs, func(i, j int) bool {
		if by == "name" || by == "name_asc" {
			if by == "name" {
				return swLess(rs[i], rs[j])
			}
			return swLess(rs[j], rs[i])
		}
		if ki, kj := key(rs[i]), key(rs[j]); ki != kj {
			return ki > kj != asc
		}
		return swLess(rs[i], rs[j])
	})
}

func sortInstalls(is []swInstall, by string) {
	k := func(i swInstall) string {
		switch strings.TrimSuffix(by, "_asc") {
		case "computer":
			return strings.ToLower(i.Hostname)
		case "user":
			return strings.ToLower(i.User)
		case "installed":
			return i.InstallDate
		}
		return strings.ToLower(i.Publisher + "\x00" + i.Title + "\x00" + i.Version + "\x00" + i.Hostname)
	}
	asc := strings.HasSuffix(by, "_asc")
	sort.SliceStable(is, func(i, j int) bool {
		if asc {
			return k(is[j]) < k(is[i])
		}
		return k(is[i]) < k(is[j])
	})
}

func (s *Server) softwareCSV(w http.ResponseWriter, d *swData) {
	if d.View == "installs" {
		s.writeCSV(w, "software-installations.csv", []string{"computer", "user", "publisher", "title", "version", "arch", "scope", "install_date"},
			func(add func(...string)) {
				for _, i := range d.Installs {
					add(i.Hostname, i.User, i.Publisher, i.Title, i.Version, i.Arch, i.Scope, i.InstallDate)
				}
			})
		return
	}
	s.writeCSV(w, "software-"+d.View+".csv", []string{"publisher", "title", "version", "titles", "versions", "computers", "users"},
		func(add func(...string)) {
			for _, r := range d.Rows {
				add(r.Publisher, r.Title, r.Version, strconv.Itoa(r.Titles), strconv.Itoa(r.Versions), strconv.Itoa(r.Computers), strconv.Itoa(r.Users))
			}
		})
}

// vbarChart is a column chart drawn in an SVG of vbarW x vbarH units.
type vbarChart struct {
	Title, Sub string
	Bars       []vbar
	Ticks      []vtick
}

type vbar struct {
	Full, Link     string
	Lines          []string // the label, in at most two short lines
	Count          int
	X, Y, W, H, CX float64
}

type vtick struct {
	Y     float64
	Label string
}

const (
	vbarW, vbarH         = 600.0, 260.0
	vbarLeft, vbarRight  = 44.0, 8.0
	vbarTop, vbarBottom  = 24.0, 46.0
	vbarLabelRunes       = 12
	vbarTicks            = 4
	vbarSlotFill         = 0.7
	vbarMinVisibleHeight = 1.0
)

// newVBars draws the first maxSoftwareCharts rows (already sorted by
// computers) as columns.
func newVBars(title, sub string, rows []swRow, label func(swRow) string) vbarChart {
	c := vbarChart{Title: title, Sub: sub}
	if len(rows) > maxSoftwareCharts {
		rows = rows[:maxSoftwareCharts]
	}
	if len(rows) == 0 {
		return c
	}
	top := niceCeil(rows[0].Computers)
	plotH := vbarH - vbarTop - vbarBottom
	for i := 0; i <= vbarTicks; i++ {
		n := top * i / vbarTicks
		c.Ticks = append(c.Ticks, vtick{Y: vbarH - vbarBottom - plotH*float64(n)/float64(top), Label: strconv.Itoa(n)})
	}
	slot := (vbarW - vbarLeft - vbarRight) / float64(maxSoftwareCharts)
	for i, r := range rows {
		full := label(r)
		if full == "" {
			full = "—"
		}
		h := math.Max(plotH*float64(r.Computers)/float64(top), vbarMinVisibleHeight)
		x := vbarLeft + slot*float64(i) + slot*(1-vbarSlotFill)/2
		c.Bars = append(c.Bars, vbar{Lines: labelLines(full, vbarLabelRunes), Full: full, Link: r.Link, Count: r.Computers,
			X: x, W: slot * vbarSlotFill, H: h, Y: vbarH - vbarBottom - h, CX: x + slot*vbarSlotFill/2})
	}
	return c
}

// niceCeil rounds n up to 1, 2 or 5 times a power of ten, and to a
// multiple of the tick count so the ticks are whole numbers.
func niceCeil(n int) int {
	if n < vbarTicks {
		return vbarTicks
	}
	p := math.Pow(10, math.Floor(math.Log10(float64(n))))
	for _, m := range []float64{1, 2, 5, 10} {
		if v := int(m * p); v >= n && v%vbarTicks == 0 {
			return v
		}
	}
	return (n + vbarTicks - 1) / vbarTicks * vbarTicks
}

// labelLines splits s in two lines of at most n runes, after a space, dot
// or dash when there is one, shortening the second.
func labelLines(s string, n int) []string {
	if utf8.RuneCountInString(s) <= n {
		return []string{s}
	}
	r := []rune(s)
	cut := n
	for i := n; i > n/2; i-- {
		if r[i-1] == ' ' || r[i-1] == '.' || r[i-1] == '-' {
			cut = i
			break
		}
	}
	return []string{string(r[:cut]), shorten(strings.TrimSpace(string(r[cut:])), n)}
}

func shorten(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// ViewBox is the viewBox of the chart's SVG.
func (vbarChart) ViewBox() string { return fmt.Sprintf("0 0 %g %g", vbarW, vbarH) }

// Axis are the coordinates of the chart's axes.
func (vbarChart) Axis() map[string]float64 {
	return map[string]float64{"Left": vbarLeft, "Right": vbarW - vbarRight, "Base": vbarH - vbarBottom, "Label": vbarH - vbarBottom + 16}
}
