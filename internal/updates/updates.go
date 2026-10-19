// Package updates normalizes the reports of the winupdate, winget and
// firmware modules and ranks endpoints by how far behind they are.
package updates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Modules whose results are update reports.
const (
	WindowsModule  = "winupdate"
	WingetModule   = "winget"
	FirmwareModule = "firmware"
	SourceWindows  = "windows"
	SourceWinget   = "winget"
	SourceFirmware = "firmware"
)

const (
	maxItems  = 2000
	maxString = 512
)

// SourceOf returns the report source of a module action, or "".
func SourceOf(module, action string) string {
	switch {
	case module == WindowsModule && (action == "scan" || action == "install"):
		return SourceWindows
	case module == WingetModule && (action == "scan" || action == "upgrade"):
		return SourceWinget
	case module == FirmwareModule && (action == "scan" || action == "install"):
		return SourceFirmware
	}
	return ""
}

// WindowsUpdate is a missing Windows update.
type WindowsUpdate struct {
	ID             string     `json:"id"`
	Title          string     `json:"title"`
	KBs            []string   `json:"kbs,omitempty"`
	Classification string     `json:"classification,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	Released       *time.Time `json:"released,omitempty"`
	SizeBytes      int64      `json:"size_bytes,omitempty"`
}

// Important reports whether the update is a security or critical update.
func (u WindowsUpdate) Important() bool {
	return u.Classification == "security" || u.Classification == "critical"
}

// PendingReboot describes a pending reboot.
type PendingReboot struct {
	Required bool       `json:"required"`
	Reasons  []string   `json:"reasons,omitempty"`
	Since    *time.Time `json:"since,omitempty"`
}

// WindowsReport is a normalized winupdate result.
type WindowsReport struct {
	ManagedBy     string          `json:"managed_by"` // none | wsus | intune
	WSUSServer    string          `json:"wsus_server,omitempty"`
	ScannedAt     time.Time       `json:"scanned_at"`
	Updates       []WindowsUpdate `json:"updates"`
	PendingReboot PendingReboot   `json:"pending_reboot"`
	LastSuccess   *time.Time      `json:"last_success,omitempty"`
}

// App is a third-party application with an available upgrade.
type App struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Version   string `json:"version,omitempty"`
	Available string `json:"available,omitempty"`
	Source    string `json:"source,omitempty"`
}

// WingetReport is a normalized winget result.
type WingetReport struct {
	ScannedAt time.Time `json:"scanned_at"`
	Upgrades  []App     `json:"upgrades"`
}

var (
	kbRe       = regexp.MustCompile(`^KB\d{4,8}$`)
	wingetIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	classes    = map[string]bool{"security": true, "critical": true, "rollup": true, "update": true, "definition": true,
		"feature_pack": true, "service_pack": true, "upgrade": true, "tools": true, "driver": true}
)

func clip(s string) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, ""))
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > maxString {
		s = s[:maxString]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func decode(raw []byte, v any) error {
	return json.NewDecoder(bytes.NewReader(raw)).Decode(v)
}

// ParseWindows normalizes a winupdate result.
func ParseWindows(raw []byte, now time.Time) (*WindowsReport, error) {
	r := &WindowsReport{}
	if err := decode(raw, r); err != nil {
		return nil, fmt.Errorf("winupdate report: %w", err)
	}
	switch r.ManagedBy {
	case "none", "wsus", "intune":
	default:
		r.ManagedBy = "none"
	}
	r.WSUSServer = clip(r.WSUSServer)
	if r.ScannedAt.IsZero() || r.ScannedAt.After(now.Add(5*time.Minute)) {
		r.ScannedAt = now
	}
	r.ScannedAt = r.ScannedAt.UTC()
	if len(r.Updates) > maxItems {
		r.Updates = r.Updates[:maxItems]
	}
	out := r.Updates[:0]
	for _, u := range r.Updates {
		u.ID, u.Title, u.Severity = clip(u.ID), clip(u.Title), clip(u.Severity)
		if u.Title == "" {
			continue
		}
		if !classes[u.Classification] {
			u.Classification = ""
		}
		var kbs []string
		for _, k := range u.KBs {
			if k = strings.ToUpper(clip(k)); kbRe.MatchString(k) {
				kbs = append(kbs, k)
			}
		}
		u.KBs, u.SizeBytes = kbs, max(u.SizeBytes, 0)
		out = append(out, u)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Important() != out[j].Important() {
			return out[i].Important()
		}
		return released(out[i]).Before(released(out[j]))
	})
	r.Updates = out
	var reasons []string
	for _, x := range r.PendingReboot.Reasons {
		if x = clip(x); x != "" && len(reasons) < 10 {
			reasons = append(reasons, x)
		}
	}
	r.PendingReboot.Reasons = reasons
	return r, nil
}

func released(u WindowsUpdate) time.Time {
	if u.Released == nil {
		return time.Time{}
	}
	return *u.Released
}

// ParseWinget normalizes a winget result.
func ParseWinget(raw []byte, now time.Time) (*WingetReport, error) {
	r := &WingetReport{}
	if err := decode(raw, r); err != nil {
		return nil, fmt.Errorf("winget report: %w", err)
	}
	if r.ScannedAt.IsZero() || r.ScannedAt.After(now.Add(5*time.Minute)) {
		r.ScannedAt = now
	}
	r.ScannedAt = r.ScannedAt.UTC()
	if len(r.Upgrades) > maxItems {
		r.Upgrades = r.Upgrades[:maxItems]
	}
	out := r.Upgrades[:0]
	for _, a := range r.Upgrades {
		a.Name, a.ID, a.Version, a.Available, a.Source = clip(a.Name), clip(a.ID), clip(a.Version), clip(a.Available), clip(a.Source)
		if wingetIDRe.MatchString(a.ID) {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	r.Upgrades = out
	return r, nil
}

// Summary holds the counters kept per agent.
type Summary struct {
	Important   int        // security + critical
	Other       int        // other missing updates
	OldestDays  int        // age of the oldest missing important update
	Behind      int        // Patch Tuesdays since the oldest missing important update
	Reboot      bool       // reboot pending
	RebootSince *time.Time // since when
}

// Summarize computes the counters of a Windows report.
func (r *WindowsReport) Summarize(now time.Time) Summary {
	s := Summary{Reboot: r.PendingReboot.Required, RebootSince: r.PendingReboot.Since}
	var oldest time.Time
	for _, u := range r.Updates {
		if !u.Important() {
			s.Other++
			continue
		}
		s.Important++
		if t := released(u); !t.IsZero() && (oldest.IsZero() || t.Before(oldest)) {
			oldest = t
		}
	}
	if !oldest.IsZero() {
		s.OldestDays = int(now.Sub(oldest).Hours() / 24)
		s.Behind = PatchTuesdaysBetween(oldest, now)
	}
	return s
}

// PatchTuesday returns the second Tuesday of t's month.
func PatchTuesday(year int, month time.Month) time.Time {
	first := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	offset := (int(time.Tuesday) - int(first.Weekday()) + 7) % 7
	return first.AddDate(0, 0, offset+7)
}

// PatchTuesdaysBetween counts the Patch Tuesdays after from and up to to.
func PatchTuesdaysBetween(from, to time.Time) int {
	n := 0
	y, m := from.Year(), from.Month()
	for i := 0; i < 240; i++ {
		pt := PatchTuesday(y, m)
		if pt.After(to) {
			break
		}
		if pt.After(from) {
			n++
		}
		m++
		if m > 12 {
			m, y = 1, y+1
		}
	}
	return n
}

// Score ranks how far behind an endpoint is: higher is worse.
func Score(s Summary, thirdParty int, now time.Time) int {
	score := s.Important*10 + s.Behind*15 + min(s.OldestDays, 180)/3 + s.Other + thirdParty*2
	if s.Reboot && s.RebootSince != nil {
		score += min(int(now.Sub(*s.RebootSince).Hours()/24), 30) * 2
	} else if s.Reboot {
		score += 2
	}
	return score
}

// FirmwareUpdate is a BIOS, firmware, driver or vendor application update.
type FirmwareUpdate struct {
	ID        string     `json:"id,omitempty"`
	Title     string     `json:"title"`
	Version   string     `json:"version,omitempty"`
	Category  string     `json:"category"` // bios | firmware | driver | application | other
	Severity  string     `json:"severity"` // critical | recommended | optional
	Released  *time.Time `json:"released,omitempty"`
	SizeBytes int64      `json:"size_bytes,omitempty"`
}

// FirmwareReport is a normalized firmware result.
type FirmwareReport struct {
	ScannedAt   time.Time        `json:"scanned_at"`
	Vendor      string           `json:"vendor"`
	Supported   bool             `json:"supported"`
	Tool        string           `json:"tool,omitempty"`
	ToolMissing string           `json:"tool_missing,omitempty"`
	Updates     []FirmwareUpdate `json:"updates"`
}

var (
	fwCategories = map[string]bool{"bios": true, "firmware": true, "driver": true, "application": true, "other": true}
	fwSeverities = map[string]bool{"critical": true, "recommended": true, "optional": true}
)

// ParseFirmware normalizes a firmware result.
func ParseFirmware(raw []byte, now time.Time) (*FirmwareReport, error) {
	r := &FirmwareReport{}
	if err := decode(raw, r); err != nil {
		return nil, fmt.Errorf("firmware report: %w", err)
	}
	if r.ScannedAt.IsZero() || r.ScannedAt.After(now.Add(5*time.Minute)) {
		r.ScannedAt = now
	}
	r.ScannedAt = r.ScannedAt.UTC()
	r.Vendor, r.Tool, r.ToolMissing = clip(r.Vendor), clip(r.Tool), clip(r.ToolMissing)
	if len(r.Updates) > maxItems {
		r.Updates = r.Updates[:maxItems]
	}
	out := r.Updates[:0]
	for _, u := range r.Updates {
		u.ID, u.Title, u.Version = clip(u.ID), clip(u.Title), clip(u.Version)
		if u.Title == "" {
			continue
		}
		if !fwCategories[u.Category] {
			u.Category = "other"
		}
		if !fwSeverities[u.Severity] {
			u.Severity = "optional"
		}
		out = append(out, u)
	}
	// BIOS first, then by severity.
	rank := map[string]int{"critical": 0, "recommended": 1, "optional": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Category == "bios") != (out[j].Category == "bios") {
			return out[i].Category == "bios"
		}
		return rank[out[i].Severity] < rank[out[j].Severity]
	})
	r.Updates = out
	return r, nil
}

// Counts returns the critical updates, the others, and whether a BIOS
// update is pending.
func (r *FirmwareReport) Counts() (critical, other int, bios bool) {
	for _, u := range r.Updates {
		if u.Severity == "critical" {
			critical++
		} else {
			other++
		}
		bios = bios || u.Category == "bios"
	}
	return
}
