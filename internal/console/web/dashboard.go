package web

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/inventory"
	"github.com/stefanozanarini/open-rmm/internal/updates"
)

// The Reporting dashboard: aggregates over every agent of the tenant, as
// stat tiles, part-to-whole donuts (at most five segments, status colors
// with a label and count beside each) and horizontal bars for
// distributions with more classes. Charts are SVG rendered here; hovering a
// segment shows its value, and segments link to the filtered view when one
// exists.

const (
	donutR      = 42.0
	donutStroke = 14.0
	donutGap    = 2.0 // surface gap between segments
	maxBars     = 6
	barGap      = 0.8 // between stacked segments, in viewBox units
	maxOutdated = 10
	maxSoftware = 12
)

type dashData struct {
	Total, Online, Problems, Pending, Unseen int
	Donuts                                   []donut
	Bars                                     []barChart
}

type donut struct {
	Title, Sub string
	Total      int
	Segs       []seg
}

// seg is a donut segment; Class picks its color token.
type seg struct {
	Label, Class, Link string
	Count              int
	Pct                int
	Dash, Gap, Offset  string // SVG stroke geometry
}

type barChart struct {
	Title, Sub string
	Wide       bool   // spans two grid columns
	Legend     []seg  // series of stacked bars (Label and Class)
	Empty      string // shown when there are no bars
	Bars       []bar
}

type bar struct {
	Label, Link string
	Count       int
	Width       float64 // % of the largest bar
	Note        string  // shown after the label, muted
	Parts       []part  // stacked segments; none for a single bar
}

// part is a segment of a stacked bar, in viewBox units (0-100).
type part struct {
	Label, Class string
	Count        int
	X, W         float64
}

func newDonut(title, sub string, segs []seg) donut {
	d := donut{Title: title, Sub: sub}
	for _, s := range segs {
		d.Total += s.Count
	}
	if d.Total == 0 {
		return d
	}
	c := 2 * math.Pi * donutR
	shown := 0
	for _, s := range segs {
		if s.Count > 0 {
			shown++
		}
	}
	at := 0.0
	for _, s := range segs {
		if s.Count == 0 {
			continue
		}
		l := c * float64(s.Count) / float64(d.Total)
		dash := l
		if shown > 1 {
			dash = math.Max(l-donutGap, 0.5)
		}
		s.Pct = int(math.Round(100 * float64(s.Count) / float64(d.Total)))
		s.Dash, s.Gap, s.Offset = fmt.Sprintf("%.2f", dash), fmt.Sprintf("%.2f", c-dash), fmt.Sprintf("%.2f", -at)
		at += l
		d.Segs = append(d.Segs, s)
	}
	return d
}

func newBars(title, sub string, bars []bar) barChart {
	max := 0
	for _, b := range bars {
		max = int(math.Max(float64(max), float64(b.Count)))
	}
	for i := range bars {
		if max == 0 {
			continue
		}
		bars[i].Width = 100 * float64(bars[i].Count) / float64(max)
		var parts []part
		x := 0.0
		for _, p := range bars[i].Parts {
			if p.Count == 0 {
				continue
			}
			p.X, p.W = x, 100*float64(p.Count)/float64(max)
			x += p.W
			parts = append(parts, p)
		}
		// A surface gap between stacked segments.
		for j := range parts {
			if j < len(parts)-1 {
				parts[j].W = math.Max(parts[j].W-barGap, 0.5)
			}
		}
		bars[i].Parts = parts
	}
	return barChart{Title: title, Sub: sub, Bars: bars}
}

// softwareFamily names an application without its version, edition
// details or architecture, so that "Java 8 Update 401 (64-bit)" and
// "Java 8 Update 431" count as Java. It returns the name and the prefix to
// search for in the computers report.
func softwareFamily(name string) (label, search string) {
	n := name
	for {
		i := strings.IndexByte(n, '(')
		j := strings.IndexByte(n, ')')
		if i < 0 || j < i {
			break
		}
		n = n[:i] + n[j+1:]
	}
	if i := strings.Index(n, " - "); i > 0 {
		n = n[:i]
	}
	var kept []string
	cut := false // a token was dropped: the search stops before it
	var prefix []string
	f := strings.Fields(n)
	for i, tok := range f {
		drop := versionRe.MatchString(tok) || (strings.EqualFold(tok, "update") && i > 0 && versionRe.MatchString(f[i-1]))
		if strings.EqualFold(tok, "x64") || strings.EqualFold(tok, "x86") || strings.EqualFold(tok, "64-bit") || strings.EqualFold(tok, "32-bit") {
			drop = true
		}
		if drop {
			cut = true
			continue
		}
		kept = append(kept, tok)
		if !cut {
			prefix = append(prefix, tok)
		}
	}
	label = strings.Join(kept, " ")
	if label == "" {
		label = strings.TrimSpace(name)
	}
	search = strings.Join(prefix, " ")
	if search == "" {
		search = label
	}
	return label, search
}

// versionRe matches version-like tokens: 24.08, v2.1, 2015-2022, 401.
var versionRe = regexp.MustCompile(`^v?\d[\d.\-_]*[a-z]?$`)

// runtimeNoise lists components installed with Windows or with other
// software rather than by users; they are left out of the popular software.
var runtimeNoise = []string{"Microsoft Visual C++", "Microsoft .NET", ".NET ", "Microsoft Windows Desktop Runtime",
	"Microsoft ASP.NET", "Microsoft Edge WebView2", "Microsoft Update Health Tools", "Update for Windows",
	"Windows SDK", "Windows Software Development Kit", "Microsoft Windows SDK", "vs_", "Microsoft GameInput"}

func isRuntime(name string) bool {
	for _, p := range runtimeNoise {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// osFamily names an operating system for the distribution chart: product
// and release, without the vendor and the edition details.
func osFamily(a store.Agent, inv *inventory.Inventory) string {
	if inv == nil || inv.OS.Name == "" {
		if a.Host.OSVersion != "" {
			return a.Host.OSVersion
		}
		return a.Host.OS
	}
	n := strings.TrimPrefix(inv.OS.Name, "Microsoft ")
	if inv.OS.DisplayVersion != "" && !strings.Contains(n, "Server") {
		n += " " + inv.OS.DisplayVersion
	}
	return n
}

func (s *Server) dashboard(ctx context.Context, lang, t string) (*dashData, error) {
	agents, err := s.store.ListAgents(ctx, t)
	if err != nil {
		return nil, err
	}
	worst, err := s.store.WorstChecks(ctx, t)
	if err != nil {
		return nil, err
	}
	invs, err := s.store.ListInventories(ctx, t)
	if err != nil {
		return nil, err
	}
	byInv := map[string]*inventory.Inventory{}
	for _, i := range invs {
		if p, err := inventory.Parse(i.Data); err == nil {
			byInv[i.AgentID] = p
		}
	}
	statuses, err := s.store.ListUpdateStatus(ctx, t, "")
	if err != nil {
		return nil, err
	}
	win := map[string]store.UpdateStatus{}
	third := map[string]int{}
	for _, st := range statuses {
		switch st.Source {
		case updates.SourceWindows:
			win[st.AgentID] = st
		case updates.SourceWinget:
			third[st.AgentID] = st.ThirdParty
		}
	}
	now := s.now()
	d := &dashData{}
	type state struct{ off, fail, warn, ok int }
	var srv, ws state
	types := map[string]int{}
	osCount := map[string]int{}
	versions := map[string]int{}
	var boot [6]int // <7d, 7-30, 30-60, 60-90, >90, unknown
	var patch [5]int
	var av, disk, bl [4]int // ok, warning, critical, no data
	var outdated []bar
	type swFamily struct {
		search   string
		pcs      int
		versions map[string]bool
	}
	software := map[string]*swFamily{}
	for _, a := range agents {
		switch a.Status {
		case store.AgentRevoked:
			continue
		case store.AgentPending:
			d.Pending++
			continue
		}
		d.Total++
		online := s.online(a)
		if online {
			d.Online++
		}
		if a.LastSeenAt == nil || now.Sub(*a.LastSeenAt) > 7*24*time.Hour {
			d.Unseen++
		}
		inv := byInv[a.ID]
		st, hasWin := win[a.ID]
		reboot := hasWin && st.Reboot
		w := worst[a.ID]
		if w == store.CheckFailing {
			d.Problems++
		}
		target := &ws
		if a.Host.OSFamily == "server" {
			target = &srv
		}
		switch {
		case !online:
			target.off++
		case w == store.CheckFailing:
			target.fail++
		case w == store.CheckWarning || reboot:
			target.warn++
		default:
			target.ok++
		}
		switch {
		case a.Host.OSFamily == "server":
			types["server"]++
		case inv != nil && len(inv.Batteries) > 0:
			types["laptop"]++
		default:
			types["desktop"]++
		}
		osCount[osFamily(a, inv)]++
		versions[a.Host.AgentVersion]++
		switch {
		case inv == nil || inv.OS.LastBoot == nil:
			boot[5]++
		case now.Sub(*inv.OS.LastBoot) < 7*24*time.Hour:
			boot[0]++
		case now.Sub(*inv.OS.LastBoot) < 30*24*time.Hour:
			boot[1]++
		case now.Sub(*inv.OS.LastBoot) < 60*24*time.Hour:
			boot[2]++
		case now.Sub(*inv.OS.LastBoot) < 90*24*time.Hour:
			boot[3]++
		default:
			boot[4]++
		}
		switch {
		case !hasWin || now.Sub(st.ScannedAt) > staleScan:
			patch[4]++
		case st.Behind > 1:
			patch[0]++
		case st.Important > 0:
			patch[1]++
		case st.Reboot:
			patch[2]++
		default:
			patch[3]++
		}
		// Antivirus, from the protection-status check.
		avState := 3
		if checks, err := s.store.ListChecks(ctx, t, a.ID); err == nil {
			for _, c := range checks {
				if c.CheckID == "protection-status/antivirus" {
					avState = map[string]int{store.CheckOK: 0, store.CheckWarning: 1, store.CheckFailing: 2}[c.Status]
				}
			}
		}
		av[avState]++
		// Free space: the fullest fixed volume.
		diskState := 3
		if inv != nil {
			minFree := 101.0
			for _, v := range inv.Volumes {
				if v.SizeBytes > 1<<30 {
					minFree = math.Min(minFree, 100*float64(v.FreeBytes)/float64(v.SizeBytes))
				}
			}
			switch {
			case minFree > 100:
			case minFree < 10:
				diskState = 2
			case minFree < 20:
				diskState = 1
			default:
				diskState = 0
			}
		}
		disk[diskState]++
		// BitLocker on the system volume.
		blState := 3
		if inv != nil {
			for _, v := range inv.Volumes {
				if strings.EqualFold(strings.TrimSuffix(v.Mount, `\`), "C:") {
					switch v.BitLocker {
					case "on":
						blState = 0
					case "encrypting", "suspended", "decrypting":
						blState = 1
					case "off":
						blState = 2
					}
				}
			}
		}
		bl[blState]++
		// Pending updates: Windows (important and other) and applications.
		if n := st.Important + st.Other + third[a.ID]; n > 0 {
			outdated = append(outdated, bar{Label: a.Host.Hostname, Link: "/agents/" + a.ID + "#patches", Count: n,
				Note: osFamily(a, inv), Parts: []part{
					{Label: tr(lang, "Windows Update"), Class: "cat-1", Count: st.Important + st.Other},
					{Label: tr(lang, "Applicazioni"), Class: "cat-2", Count: third[a.ID]},
				}})
		}
		// Installed applications, each family counted once per computer.
		if inv != nil {
			seen := map[string]bool{}
			for _, sw := range inv.VisibleSoftware() {
				if isRuntime(sw.Name) {
					continue
				}
				label, search := softwareFamily(sw.Name)
				f := software[label]
				if f == nil {
					f = &swFamily{search: search, versions: map[string]bool{}}
					software[label] = f
				}
				if sw.Version != "" {
					f.versions[sw.Version] = true
				}
				if !seen[label] {
					seen[label] = true
					f.pcs++
				}
			}
		}
	}

	q := func(kv ...string) string {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v.Encode()
	}
	stateDonut := func(title, family string, x state) donut {
		link := "/agents?" + q("family", family)
		return newDonut(title, tr(lang, "per stato, il peggiore per ogni agente"), []seg{
			{Label: tr(lang, "Controlli falliti"), Class: "st-critical", Count: x.fail, Link: link},
			{Label: tr(lang, "Avviso o riavvio in sospeso"), Class: "st-warning", Count: x.warn, Link: link},
			{Label: tr(lang, "Offline"), Class: "st-none", Count: x.off, Link: link},
			{Label: "OK", Class: "st-good", Count: x.ok, Link: link},
		})
	}
	d.Donuts = append(d.Donuts,
		stateDonut(tr(lang, "Server"), "server", srv),
		stateDonut(tr(lang, "Workstation"), "client", ws),
		newDonut(tr(lang, "Tipi di dispositivo"), tr(lang, "tutti gli agenti approvati"), []seg{
			{Label: tr(lang, "Server"), Class: "cat-1", Count: types["server"], Link: "/agents?" + q("family", "server")},
			{Label: tr(lang, "Desktop"), Class: "cat-2", Count: types["desktop"], Link: "/agents?" + q("family", "client")},
			{Label: tr(lang, "Portatili"), Class: "cat-3", Count: types["laptop"], Link: "/agents?" + q("family", "client")},
		}),
		newDonut(tr(lang, "Patch di Windows"), tr(lang, "il caso peggiore per ogni agente"), []seg{
			{Label: tr(lang, "Indietro di più di un Patch Tuesday"), Class: "st-critical", Count: patch[0], Link: "/patches?" + q("show", "behind")},
			{Label: tr(lang, "Aggiornamenti di sicurezza mancanti"), Class: "st-serious", Count: patch[1], Link: "/patches?" + q("show", "missing")},
			{Label: tr(lang, "Riavvio in sospeso"), Class: "st-warning", Count: patch[2], Link: "/patches?" + q("show", "reboot")},
			{Label: tr(lang, "Non verificati da 7 giorni"), Class: "st-none", Count: patch[4], Link: "/patches?" + q("show", "stale")},
			{Label: tr(lang, "In regola"), Class: "st-good", Count: patch[3], Link: "/patches?" + q("show", "compliant")},
		}),
		newDonut(tr(lang, "Antivirus"), tr(lang, "dal controllo protection-status"), []seg{
			{Label: tr(lang, "Assente o disattivato"), Class: "st-critical", Count: av[2]},
			{Label: tr(lang, "Da verificare"), Class: "st-warning", Count: av[1]},
			{Label: tr(lang, "Nessun dato"), Class: "st-none", Count: av[3]},
			{Label: tr(lang, "Attivo"), Class: "st-good", Count: av[0]},
		}),
		newDonut(tr(lang, "Spazio disco"), tr(lang, "il volume più pieno di ogni agente"), []seg{
			{Label: tr(lang, "Libero: meno del 10%"), Class: "st-critical", Count: disk[2]},
			{Label: tr(lang, "Libero: meno del 20%"), Class: "st-warning", Count: disk[1]},
			{Label: tr(lang, "Nessun dato"), Class: "st-none", Count: disk[3]},
			{Label: tr(lang, "Spazio sufficiente"), Class: "st-good", Count: disk[0]},
		}),
		newDonut("BitLocker", tr(lang, "volume di sistema"), []seg{
			{Label: tr(lang, "Non cifrato"), Class: "st-critical", Count: bl[2]},
			{Label: tr(lang, "Sospeso o in corso"), Class: "st-warning", Count: bl[1]},
			{Label: tr(lang, "Nessun dato"), Class: "st-none", Count: bl[3]},
			{Label: tr(lang, "Cifrato"), Class: "st-good", Count: bl[0]},
		}),
	)
	// Distributions with more classes: bars, the largest first, the rest
	// folded into "Other".
	ranked := func(m map[string]int, link func(string) string) []bar {
		var out []bar
		for k, n := range m {
			if k == "" {
				k = "?"
			}
			out = append(out, bar{Label: k, Count: n})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Count != out[j].Count {
				return out[i].Count > out[j].Count
			}
			return out[i].Label < out[j].Label
		})
		if len(out) > maxBars {
			other := bar{Label: tr(lang, "Altri")}
			for _, b := range out[maxBars-1:] {
				other.Count += b.Count
			}
			out = append(out[:maxBars-1], other)
		}
		for i := range out {
			if link != nil && out[i].Label != tr(lang, "Altri") {
				out[i].Link = link(out[i].Label)
			}
		}
		return out
	}
	d.Bars = append(d.Bars,
		newBars(tr(lang, "Sistemi operativi"), tr(lang, "agenti per sistema e versione"), ranked(osCount, func(l string) string {
			return "/reports?" + q("tab", "computers", "os", l)
		})),
		newBars(tr(lang, "Ultimo riavvio"), tr(lang, "dall'inventario"), []bar{
			{Label: tr(lang, "meno di 7 giorni"), Count: boot[0]}, {Label: tr(lang, "7–30 giorni"), Count: boot[1]},
			{Label: tr(lang, "30–60 giorni"), Count: boot[2]}, {Label: tr(lang, "60–90 giorni"), Count: boot[3]},
			{Label: tr(lang, "oltre 90 giorni"), Count: boot[4]}, {Label: tr(lang, "sconosciuto"), Count: boot[5]},
		}),
		newBars(tr(lang, "Versioni dell'agente"), tr(lang, "agenti per versione"), ranked(versions, nil)),
	)

	sort.Slice(outdated, func(i, j int) bool {
		if outdated[i].Count != outdated[j].Count {
			return outdated[i].Count > outdated[j].Count
		}
		return strings.ToLower(outdated[i].Label) < strings.ToLower(outdated[j].Label)
	})
	if len(outdated) > maxOutdated {
		outdated = outdated[:maxOutdated]
	}
	old := newBars(tr(lang, "Computer più indietro con gli aggiornamenti"),
		tr(lang, "aggiornamenti di Windows e delle applicazioni da installare, dall'ultima verifica"), outdated)
	old.Wide, old.Empty = true, tr(lang, "Nessun computer con aggiornamenti da installare.")
	old.Legend = []seg{{Label: tr(lang, "Windows Update"), Class: "cat-1"}, {Label: tr(lang, "Applicazioni"), Class: "cat-2"}}

	var popular []bar
	for label, f := range software {
		b := bar{Label: label, Count: f.pcs, Link: "/reports?" + q("tab", "computers", "software", f.search)}
		if n := len(f.versions); n > 1 {
			b.Note = trf(lang, "%d versioni", n)
		}
		popular = append(popular, b)
	}
	sort.Slice(popular, func(i, j int) bool {
		if popular[i].Count != popular[j].Count {
			return popular[i].Count > popular[j].Count
		}
		return strings.ToLower(popular[i].Label) < strings.ToLower(popular[j].Label)
	})
	if len(popular) > maxSoftware {
		popular = popular[:maxSoftware]
	}
	pop := newBars(tr(lang, "Software più installati"),
		tr(lang, "computer per applicazione, senza distinguere le versioni; esclusi i componenti di sistema"), popular)
	pop.Wide, pop.Empty = true, tr(lang, "Nessun inventario ricevuto.")
	d.Bars = append(d.Bars, old, pop)
	return d, nil
}
