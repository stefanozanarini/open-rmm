package web

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/console/vuln"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

// Advanced search of Reporting → Computer inventory (?q=): terms
// field:value combined with AND, OR, NOT and parentheses, over the fields of
// the latest inventory. The fields and the syntax are listed on
// /reports/query.

const (
	maxQueryLen   = 1000
	maxQueryDepth = 30
)

// Field kinds: how values are compared.
const (
	kindText    = "text"    // contains, exact, wildcards; > < compare as versions
	kindNumber  = "number"  // = > < >= <=
	kindDate    = "date"    // YYYY-MM-DD or N days ago (-30d)
	kindBool    = "bool"    // yes / no
	kindProduct = "product" // installed software: name, or name@version
)

// queryCtx is the computer a query is evaluated on.
type queryCtx struct {
	lang string
	now  time.Time
	a    store.Agent
	inv  *inventory.Inventory // never nil: empty without inventory
	row  *reportRow
}

type queryField struct {
	Key, Label, Kind string
	values           func(c *queryCtx) []string
}

func one(s string) []string {
	if s = strings.TrimSpace(s); s == "" {
		return nil
	}
	return []string{s}
}

func boolValue(b bool) []string {
	if b {
		return []string{"yes"}
	}
	return []string{"no"}
}

func numValue(f float64, ok bool) []string {
	if !ok {
		return nil
	}
	return []string{strconv.FormatFloat(f, 'f', -1, 64)}
}

func gbValue(n int64) []string {
	return numValue(float64(n*10/(1<<30))/10, n > 0)
}

func timeValue(t *time.Time) []string {
	if t == nil || t.IsZero() {
		return nil
	}
	return []string{t.UTC().Format("2006-01-02 15:04")}
}

var queryFields = []queryField{
	{"hostname", "Nome del computer", kindText, func(c *queryCtx) []string { return one(c.a.Host.Hostname) }},
	{"site", "Sede", kindText, func(c *queryCtx) []string { return one(c.row.Site) }},
	{"user", "Utente collegato", kindText, func(c *queryCtx) []string { return one(c.row.User) }},
	{"status", "Stato", kindText, func(c *queryCtx) []string { return one(string(c.a.Status)) }},
	{"agent_version", "Versione agente", kindText, func(c *queryCtx) []string { return one(c.a.Host.AgentVersion) }},
	{"last_seen", "Ultimo contatto", kindDate, func(c *queryCtx) []string { return timeValue(c.a.LastSeenAt) }},
	{"inventory_date", "Data dell'inventario", kindDate, func(c *queryCtx) []string { return timeValue(&c.row.Seen) }},

	{"software", "Software installato (nome, o nome@versione)", kindProduct, func(c *queryCtx) []string {
		var out []string
		for _, sw := range c.inv.VisibleSoftware() {
			out = append(out, sw.Name)
		}
		return out
	}},
	{"publisher", "Produttore del software", kindText, func(c *queryCtx) []string {
		var out []string
		for _, sw := range c.inv.VisibleSoftware() {
			if sw.Publisher != "" {
				out = append(out, sw.Publisher)
			}
		}
		return out
	}},

	{"os", "Sistema operativo", kindText, func(c *queryCtx) []string { return one(c.row.OS) }},
	{"os_release", "Release del sistema (es. 24H2)", kindText, func(c *queryCtx) []string { return one(c.inv.OS.DisplayVersion) }},
	{"os_build", "Build", kindText, func(c *queryCtx) []string { return one(c.inv.OS.Build) }},
	{"os_family", "Tipo (client o server)", kindText, func(c *queryCtx) []string { return one(c.inv.OS.Family) }},
	{"os_arch", "Architettura", kindText, func(c *queryCtx) []string { return one(c.inv.OS.Architecture) }},
	{"os_install", "Sistema installato il", kindDate, func(c *queryCtx) []string { return timeValue(c.inv.OS.InstallDate) }},
	{"last_boot", "Ultimo avvio", kindDate, func(c *queryCtx) []string { return timeValue(c.inv.OS.LastBoot) }},
	{"uptime_days", "Giorni dall'ultimo avvio", kindNumber, func(c *queryCtx) []string {
		if c.inv.OS.LastBoot == nil || c.inv.OS.LastBoot.IsZero() {
			return nil
		}
		return numValue(float64(int(c.now.Sub(*c.inv.OS.LastBoot).Hours()/24)), true)
	}},
	{"screen_locked", "Schermo bloccato", kindBool, func(c *queryCtx) []string { return boolValue(c.inv.OS.ScreenLocked) }},

	{"manufacturer", "Produttore", kindText, func(c *queryCtx) []string { return one(c.inv.System.Manufacturer) }},
	{"model", "Modello", kindText, func(c *queryCtx) []string { return one(c.inv.System.Model) }},
	{"sku", "SKU", kindText, func(c *queryCtx) []string { return one(c.inv.System.SKU) }},
	{"serial", "Numero di serie", kindText, func(c *queryCtx) []string { return one(c.inv.System.Serial) }},
	{"chassis", "Tipo di chassis", kindText, func(c *queryCtx) []string { return one(c.inv.System.Chassis) }},
	{"virtual", "Virtuale", kindBool, func(c *queryCtx) []string { return boolValue(c.inv.System.Virtual) }},
	{"domain", "Dominio", kindText, func(c *queryCtx) []string { return one(c.inv.System.Domain) }},
	{"domain_joined", "In un dominio", kindBool, func(c *queryCtx) []string { return boolValue(c.inv.System.PartOfDomain) }},

	{"bios", "Versione BIOS", kindText, func(c *queryCtx) []string { return one(c.inv.Firmware.Version) }},
	{"bios_date", "Data del BIOS", kindDate, func(c *queryCtx) []string { return one(c.inv.Firmware.Date) }},
	{"uefi", "UEFI", kindBool, func(c *queryCtx) []string {
		if c.inv.Firmware.UEFI == nil {
			return nil
		}
		return boolValue(*c.inv.Firmware.UEFI)
	}},
	{"secure_boot", "Secure Boot", kindBool, func(c *queryCtx) []string {
		if c.inv.Firmware.SecureBoot == nil {
			return nil
		}
		return boolValue(*c.inv.Firmware.SecureBoot)
	}},
	{"tpm", "TPM presente", kindBool, func(c *queryCtx) []string { return boolValue(c.inv.TPM.Present) }},
	{"tpm_version", "Versione del TPM", kindText, func(c *queryCtx) []string { return one(c.inv.TPM.Version) }},

	{"cpu", "Processore", kindText, func(c *queryCtx) []string {
		var out []string
		for _, p := range c.inv.CPUs {
			out = append(out, p.Name)
		}
		return out
	}},
	{"cores", "Core", kindNumber, func(c *queryCtx) []string {
		n := 0
		for _, p := range c.inv.CPUs {
			n += p.Cores
		}
		return numValue(float64(n), n > 0)
	}},
	{"ram_gb", "RAM (GB)", kindNumber, func(c *queryCtx) []string { return gbValue(c.inv.Memory.TotalBytes) }},

	{"disk", "Modello del disco", kindText, func(c *queryCtx) []string {
		var out []string
		for _, d := range c.inv.Disks {
			out = append(out, d.Model)
		}
		return out
	}},
	{"disk_type", "Tipo di disco (SSD, HDD)", kindText, func(c *queryCtx) []string {
		var out []string
		for _, d := range c.inv.Disks {
			out = append(out, d.MediaType)
		}
		return out
	}},
	{"disk_gb", "Dimensione del disco (GB)", kindNumber, func(c *queryCtx) []string {
		var out []string
		for _, d := range c.inv.Disks {
			out = append(out, gbValue(d.SizeBytes)...)
		}
		return out
	}},
	{"disk_health", "Stato dei dischi", kindText, func(c *queryCtx) []string {
		var out []string
		for _, d := range c.inv.Disks {
			out = append(out, d.Health)
		}
		return out
	}},
	{"free_gb", "Spazio libero sul disco di sistema (GB)", kindNumber, func(c *queryCtx) []string {
		if v := systemVolume(c.inv); v != nil && v.SizeBytes > 0 {
			return numValue(float64(v.FreeBytes*10/(1<<30))/10, true)
		}
		return nil
	}},
	{"free_pct", "Spazio libero sul disco di sistema (%)", kindNumber, func(c *queryCtx) []string {
		if v := systemVolume(c.inv); v != nil && v.SizeBytes > 0 {
			return numValue(float64(v.FreeBytes*100/v.SizeBytes), true)
		}
		return nil
	}},
	{"bitlocker", "BitLocker", kindText, func(c *queryCtx) []string {
		if v := systemVolume(c.inv); v != nil {
			return one(v.BitLocker)
		}
		return nil
	}},

	{"ip", "Indirizzo IP", kindText, func(c *queryCtx) []string { return c.inv.IPv4() }},
	{"mac", "Indirizzo MAC", kindText, func(c *queryCtx) []string {
		var out []string
		for _, n := range c.inv.Network {
			out = append(out, n.MAC)
		}
		return out
	}},
	{"gateway", "Gateway", kindText, func(c *queryCtx) []string {
		var out []string
		for _, n := range c.inv.Network {
			out = append(out, n.Gateway...)
		}
		return out
	}},
	{"dns", "Server DNS", kindText, func(c *queryCtx) []string {
		var out []string
		for _, n := range c.inv.Network {
			out = append(out, n.DNS...)
		}
		return out
	}},
	{"nic", "Scheda di rete", kindText, func(c *queryCtx) []string {
		var out []string
		for _, n := range c.inv.Network {
			out = append(out, n.Name)
		}
		return out
	}},

	{"battery", "Salute della batteria (%)", kindNumber, func(c *queryCtx) []string {
		var out []string
		for _, b := range c.inv.Batteries {
			out = append(out, numValue(float64(b.HealthPercent), b.HealthPercent > 0)...)
		}
		return out
	}},
	{"monitor", "Monitor", kindText, func(c *queryCtx) []string {
		var out []string
		for _, m := range c.inv.Monitors {
			out = append(out, strings.TrimSpace(m.Manufacturer+" "+m.Model))
		}
		return out
	}},
	{"admin", "Amministratore locale", kindText, func(c *queryCtx) []string {
		var out []string
		for _, l := range c.inv.LocalAdmins {
			out = append(out, l.Name)
		}
		return out
	}},
	{"supremo", "ID Supremo", kindText, func(c *queryCtx) []string { return one(c.inv.RemoteAccess.SupremoID) }},
	{"anydesk", "ID AnyDesk", kindText, func(c *queryCtx) []string { return one(c.inv.RemoteAccess.AnyDeskID) }},
	{"teamviewer", "ID TeamViewer", kindText, func(c *queryCtx) []string { return one(c.inv.RemoteAccess.TeamViewerID) }},
}

// freeTextFields are searched by a word without a field.
var freeTextFields = []string{"hostname", "user", "os", "model", "serial", "ip"}

func fieldByKey(key string) (*queryField, bool) {
	for i := range queryFields {
		if queryFields[i].Key == key {
			return &queryFields[i], true
		}
	}
	return nil, false
}

// kindLabels name the kinds on the help page.
var kindLabels = map[string]string{
	kindText:    "testo",
	kindNumber:  "numero",
	kindDate:    "data",
	kindBool:    "sì / no",
	kindProduct: "software",
}

// queryNode is a parsed query.
type queryNode interface {
	eval(c *queryCtx) bool
}

type andNode []queryNode
type orNode []queryNode
type notNode struct{ q queryNode }

func (n andNode) eval(c *queryCtx) bool {
	for _, q := range n {
		if !q.eval(c) {
			return false
		}
	}
	return true
}

func (n orNode) eval(c *queryCtx) bool {
	for _, q := range n {
		if q.eval(c) {
			return true
		}
	}
	return false
}

func (n notNode) eval(c *queryCtx) bool { return !n.q.eval(c) }

// termNode is field op value; a word without field searches freeTextFields.
type termNode struct {
	fields []*queryField
	op     string // : = != > < >= <=
	value  string // lower case
	glob   *regexp.Regexp
	num    float64
	date   string // YYYY-MM-DD
	// Software: name and version of the same application.
	name, version string
}

func (t *termNode) eval(c *queryCtx) bool {
	for _, f := range t.fields {
		if f.Kind == kindProduct {
			if len(t.apps(c)) > 0 {
				return true
			}
			continue
		}
		if t.op == "!=" {
			if !t.matchAny(f, f.values(c)) {
				return true
			}
			continue
		}
		if t.matchAny(f, f.values(c)) {
			return true
		}
	}
	return false
}

// apps are the installed applications a software term matches.
func (t *termNode) apps(c *queryCtx) []inventory.Software {
	var out []inventory.Software
	for _, sw := range c.inv.VisibleSoftware() {
		if textMatch(sw.Name, t.name, t.glob, ":") && (t.version == "" || versionMatch(sw.Version, t.version, t.op)) {
			out = append(out, sw)
		}
	}
	return out
}

func (t *termNode) matchAny(f *queryField, values []string) bool {
	op := t.op
	if op == "!=" {
		op = "="
	}
	if t.value == "*" {
		for _, v := range values {
			if strings.TrimSpace(v) != "" {
				return true
			}
		}
		return false
	}
	for _, v := range values {
		switch f.Kind {
		case kindNumber:
			n, err := strconv.ParseFloat(v, 64)
			if err == nil && compare(n, t.num, op) {
				return true
			}
		case kindDate:
			d := v
			if len(d) > 10 {
				d = d[:10]
			}
			if op == ":" {
				if strings.HasPrefix(d, t.date) {
					return true
				}
			} else if compareStrings(d, t.date, op) {
				return true
			}
		case kindBool:
			if v == t.value {
				return true
			}
		default:
			if op == ">" || op == "<" || op == ">=" || op == "<=" {
				if versionMatch(v, t.value, op) {
					return true
				}
			} else if textMatch(v, t.value, t.glob, op) {
				return true
			}
		}
	}
	return false
}

func textMatch(v, want string, glob *regexp.Regexp, op string) bool {
	if glob != nil {
		return glob.MatchString(v)
	}
	if op == "=" {
		return strings.EqualFold(strings.TrimSpace(v), want)
	}
	return strings.Contains(strings.ToLower(v), want)
}

func versionMatch(v, want, op string) bool {
	if strings.Contains(want, "*") && (op == ":" || op == "=") {
		return globRe(want).MatchString(v)
	}
	switch op {
	case ">", "<", ">=", "<=":
		if strings.TrimSpace(v) == "" {
			return false
		}
		cmp := vuln.CompareVersions(v, want)
		return compare(float64(cmp), 0, op)
	case "=":
		return strings.EqualFold(v, want) || vuln.CompareVersions(v, want) == 0
	}
	return strings.Contains(strings.ToLower(v), want)
}

func compare(a, b float64, op string) bool {
	switch op {
	case ">":
		return a > b
	case "<":
		return a < b
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	}
	return a == b
}

func compareStrings(a, b, op string) bool {
	switch op {
	case ">":
		return a > b
	case "<":
		return a < b
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	}
	return a == b
}

// softwareTerms are the software terms of a query, to show the matching
// applications.
func softwareTerms(q queryNode) []*termNode {
	var out []*termNode
	var walk func(queryNode)
	walk = func(n queryNode) {
		switch n := n.(type) {
		case andNode:
			for _, c := range n {
				walk(c)
			}
		case orNode:
			for _, c := range n {
				walk(c)
			}
		case notNode:
			// Applications a computer does not have are not shown.
		case *termNode:
			for _, f := range n.fields {
				if f.Kind == kindProduct {
					out = append(out, n)
				}
			}
		}
	}
	if q != nil {
		walk(q)
	}
	return out
}

// queryError is a syntax error, shown to the operator in their language.
type queryError struct {
	format string
	args   []any
}

func (e *queryError) Error() string { return e.format }

func qerr(format string, args ...any) error { return &queryError{format: format, args: args} }

type queryToken struct {
	text    string
	quoted  bool // contained quotes: never an operator
	literal bool // all in quotes: free text, never field:value
	paren   byte // '(' or ')'
}

func tokenizeQuery(s string) ([]queryToken, error) {
	var toks []queryToken
	var cur strings.Builder
	quoted, inQuote, started, literal := false, false, false, false
	flush := func() {
		if started {
			toks = append(toks, queryToken{text: cur.String(), quoted: quoted, literal: literal})
		}
		cur.Reset()
		quoted, started, literal = false, false, false
	}
	for _, r := range s {
		switch {
		case inQuote:
			if r == '"' {
				inQuote = false
			} else {
				cur.WriteRune(r)
			}
		case r == '"':
			if !started {
				literal = true
			}
			inQuote, quoted, started = true, true, true
		case r == '(' || r == ')':
			flush()
			toks = append(toks, queryToken{paren: byte(r)})
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
			started, literal = true, false
		}
	}
	if inQuote {
		return nil, qerr("Virgolette non chiuse.")
	}
	flush()
	return toks, nil
}

type queryParser struct {
	toks  []queryToken
	pos   int
	depth int
	now   time.Time
}

// parseQuery parses an advanced search; an empty query is nil.
func parseQuery(s string, now time.Time) (queryNode, error) {
	if len(s) > maxQueryLen {
		return nil, qerr("Ricerca troppo lunga (al massimo %d caratteri).", maxQueryLen)
	}
	toks, err := tokenizeQuery(s)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, nil
	}
	p := &queryParser{toks: toks, now: now}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, qerr("Parentesi chiusa senza la sua apertura.")
	}
	return n, nil
}

func (p *queryParser) peekWord(words ...string) bool {
	if p.pos >= len(p.toks) {
		return false
	}
	t := p.toks[p.pos]
	if t.quoted || t.paren != 0 {
		return false
	}
	for _, w := range words {
		if strings.EqualFold(t.text, w) {
			return true
		}
	}
	return false
}

func (p *queryParser) or() (queryNode, error) {
	var parts orNode
	for {
		n, err := p.and()
		if err != nil {
			return nil, err
		}
		parts = append(parts, n)
		if !p.peekWord("OR", "||", "O") {
			break
		}
		p.pos++
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return parts, nil
}

func (p *queryParser) and() (queryNode, error) {
	var parts andNode
	for {
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		parts = append(parts, n)
		if p.peekWord("AND", "&&", "E") {
			p.pos++
			continue
		}
		// Terms next to each other are combined with AND.
		if p.pos >= len(p.toks) || p.toks[p.pos].paren == ')' || p.peekWord("OR", "||", "O") {
			break
		}
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return parts, nil
}

func (p *queryParser) unary() (queryNode, error) {
	if p.pos >= len(p.toks) {
		return nil, qerr("La ricerca finisce con un operatore: manca un termine.")
	}
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxQueryDepth {
		return nil, qerr("Troppe parentesi annidate.")
	}
	t := p.toks[p.pos]
	if p.peekWord("NOT", "!") {
		p.pos++
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		return notNode{n}, nil
	}
	if p.peekWord("AND", "&&", "E", "OR", "||", "O") {
		return nil, qerr("%s senza un termine prima.", strings.ToUpper(t.text))
	}
	switch t.paren {
	case '(':
		p.pos++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.toks) || p.toks[p.pos].paren != ')' {
			return nil, qerr("Parentesi aperta e non chiusa.")
		}
		p.pos++
		return n, nil
	case ')':
		return nil, qerr("Parentesi chiusa senza un termine prima.")
	}
	p.pos++
	text := t.text
	if !t.quoted && len(text) > 1 && text[0] == '-' {
		n, err := p.term(text[1:], false)
		if err != nil {
			return nil, err
		}
		return notNode{n}, nil
	}
	return p.term(text, t.literal)
}

var termRe = regexp.MustCompile(`^([A-Za-z_]+)(!=|>=|<=|:|=|>|<)(.*)$`)

var relativeDays = regexp.MustCompile(`^-?(\d{1,5})d$`)

var isoDay = regexp.MustCompile(`^\d{4}(-\d{2}(-\d{2})?)?$`)

func (p *queryParser) term(text string, literal bool) (queryNode, error) {
	m := termRe.FindStringSubmatch(text)
	if m == nil || literal {
		// A word without a field.
		t := &termNode{op: ":", value: strings.ToLower(text)}
		for _, k := range freeTextFields {
			f, _ := fieldByKey(k)
			t.fields = append(t.fields, f)
		}
		if strings.Contains(text, "*") {
			t.glob = globRe(text)
		}
		return t, nil
	}
	f, ok := fieldByKey(strings.ToLower(m[1]))
	if !ok {
		return nil, qerr("Campo sconosciuto: %s.", m[1])
	}
	t := &termNode{fields: []*queryField{f}, op: m[2], value: strings.ToLower(strings.TrimSpace(m[3]))}
	if t.value == "" {
		return nil, qerr("Manca il valore di %s.", f.Key)
	}
	if t.value == "*" {
		if t.op != ":" && t.op != "=" {
			return nil, qerr("%s: l'asterisco da solo vale solo con : (campo non vuoto).", f.Key)
		}
		if f.Kind == kindProduct {
			t.name, t.glob = "", nil
		}
		return t, nil
	}
	switch f.Kind {
	case kindNumber:
		n, err := strconv.ParseFloat(strings.ReplaceAll(t.value, ",", "."), 64)
		if err != nil {
			return nil, qerr("%s vuole un numero, non %q.", f.Key, m[3])
		}
		t.num = n
		if t.op == ":" {
			t.op = "="
		}
	case kindDate:
		if d := relativeDays.FindStringSubmatch(t.value); d != nil {
			n, _ := strconv.Atoi(d[1])
			t.date = p.now.AddDate(0, 0, -n).UTC().Format("2006-01-02")
		} else if isoDay.MatchString(t.value) {
			t.date = t.value
		} else {
			return nil, qerr("%s vuole una data (2026-01-31) o un numero di giorni fa (30d), non %q.", f.Key, m[3])
		}
	case kindBool:
		switch t.value {
		case "yes", "y", "si", "sì", "true", "1", "on":
			t.value = "yes"
		case "no", "n", "false", "0", "off":
			t.value = "no"
		default:
			return nil, qerr("%s vuole sì o no, non %q.", f.Key, m[3])
		}
		if t.op != ":" && t.op != "=" && t.op != "!=" {
			return nil, qerr("%s vuole sì o no: usa : oppure !=.", f.Key)
		}
	case kindProduct:
		t.name, t.version = t.value, ""
		if i := strings.LastIndex(t.value, "@"); i >= 0 {
			t.name, t.version = strings.TrimSpace(t.value[:i]), strings.TrimSpace(t.value[i+1:])
		}
		if t.name == "" {
			return nil, qerr("software: manca il nome dell'applicazione.")
		}
		if strings.Contains(t.name, "*") {
			t.glob = globRe(t.name)
		}
		if t.op == "!=" {
			// Not having the application: NOT software:…
			t.op = ":"
			return notNode{t}, nil
		}
		if t.version == "" && t.op != ":" && t.op != "=" {
			return nil, qerr("software: per confrontare la versione scrivi nome@versione, es. software>=\"7-Zip@24\".")
		}
		return t, nil
	default:
		if strings.Contains(t.value, "*") {
			t.glob = globRe(t.value)
		}
	}
	return t, nil
}

// globRe matches a whole value with * as any text, ignoring case.
func globRe(s string) *regexp.Regexp {
	parts := strings.Split(strings.ToLower(s), "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile(`(?is)^\s*` + strings.Join(parts, ".*") + `\s*$`)
}

// queryErrorText is the error in the operator's language.
func queryErrorText(lang string, err error) string {
	var qe *queryError
	if errors.As(err, &qe) {
		if len(qe.args) == 0 {
			return tr(lang, qe.format)
		}
		return trf(lang, qe.format, qe.args...)
	}
	return err.Error()
}

type queryExample struct{ Query, Label string }

var queryExamples = []queryExample{
	{`software:"7-Zip" AND NOT software:"7-Zip@24*"`, "7-Zip installato ma non nella versione 24"},
	{`(model:Latitude OR model:OptiPlex) AND ram_gb<16`, "Dell Latitude o OptiPlex con meno di 16 GB di RAM"},
	{`os_family:client AND bitlocker!=on`, "client con il disco di sistema non cifrato"},
	{`secure_boot:no OR tpm:no`, "computer senza Secure Boot o senza TPM"},
	{`last_seen<30d`, "computer non visti da più di 30 giorni"},
	{`free_pct<10 OR free_gb<5`, "poco spazio libero sul disco di sistema"},
	{`agent_version<1.1.3 status:active`, "agenti approvati con una versione precedente alla 1.1.3"},
	{`software<"Google Chrome@142"`, "Chrome precedente alla 142"},
	{`hostname:VWUK* -virtual:yes`, "computer fisici il cui nome inizia con VWUK"},
	{`battery<70`, "portatili con la batteria sotto il 70 per cento della capacità originale"},
	{`uptime_days>30`, "computer non riavviati da più di 30 giorni"},
	{`NOT software:"Trend Micro*"`, "computer senza Trend Micro"},
}

type queryHelpField struct{ Key, Label, Kind string }

type queryHelpData struct {
	Fields   []queryHelpField
	Examples []queryExample
}

func (s *Server) handleReportQuery(w http.ResponseWriter, r *http.Request) {
	d := queryHelpData{Examples: queryExamples}
	for _, f := range queryFields {
		d.Fields = append(d.Fields, queryHelpField{Key: f.Key, Label: f.Label, Kind: kindLabels[f.Kind]})
	}
	s.render(w, r, "reportquery", s.T(r, "Ricerca avanzata nell'inventario"), d)
}
