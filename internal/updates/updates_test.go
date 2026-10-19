package updates

import (
	"testing"
	"time"
)

func TestPatchTuesday(t *testing.T) {
	cases := map[time.Month]int{time.October: 14, time.November: 11, time.December: 9}
	for m, day := range cases {
		if got := PatchTuesday(2025, m); got.Day() != day || got.Weekday() != time.Tuesday {
			t.Errorf("%s 2025: %s", m, got)
		}
	}
	from := time.Date(2025, 9, 20, 0, 0, 0, 0, time.UTC)
	if n := PatchTuesdaysBetween(from, time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)); n != 2 {
		t.Fatalf("between = %d", n)
	}
}

func TestParseWindows(t *testing.T) {
	now := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	r, err := ParseWindows([]byte(`{"managed_by":"weird","scanned_at":"2030-01-01T00:00:00Z","updates":[
	 {"title":"Defender definitions","classification":"definition","kbs":["KB2267602"]},
	 {"title":"2025-10 Cumulative Update","classification":"security","kbs":["KB5066835","kb1; rm -rf"],"released":"2025-10-14T17:00:00Z"},
	 {"title":"","classification":"security"}],
	 "pending_reboot":{"required":true,"reasons":["windows_update"],"since":"2025-11-25T00:00:00Z"}}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if r.ManagedBy != "none" || !r.ScannedAt.Equal(now) || len(r.Updates) != 2 || r.Updates[0].Classification != "security" ||
		len(r.Updates[0].KBs) != 1 {
		t.Fatalf("report = %+v", r)
	}
	s := r.Summarize(now)
	if s.Important != 1 || s.Other != 1 || s.OldestDays != 47 || s.Behind != 1 || !s.Reboot {
		t.Fatalf("summary = %+v", s)
	}
	if Score(s, 3, now) <= Score(Summary{}, 0, now) {
		t.Fatal("score")
	}
}

func TestParseWinget(t *testing.T) {
	r, err := ParseWinget([]byte(`{"upgrades":[{"name":"Zoom","id":"Zoom.Zoom","version":"5","available":"6"},{"name":"bad","id":"--force"}]}`), time.Now())
	if err != nil || len(r.Upgrades) != 1 || r.Upgrades[0].ID != "Zoom.Zoom" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestParseFirmware(t *testing.T) {
	now := time.Now()
	r, err := ParseFirmware([]byte(`{"vendor":"dell","supported":true,"tool":"Dell Command Update","updates":[
	 {"title":"Intel Wi-Fi Driver","category":"driver","severity":"recommended"},
	 {"title":"Dell BIOS Update","version":"1.21.0","category":"bios","severity":"critical"},
	 {"title":"Weird","category":"x","severity":"y"},
	 {"title":"","category":"driver"}]}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Updates) != 3 || r.Updates[0].Category != "bios" || r.Updates[2].Category != "other" || r.Updates[2].Severity != "optional" {
		t.Fatalf("updates = %+v", r.Updates)
	}
	critical, other, bios := r.Counts()
	if critical != 1 || other != 2 || !bios || r.ScannedAt.IsZero() {
		t.Fatalf("counts = %d %d %v", critical, other, bios)
	}
	if SourceOf("firmware", "install") != SourceFirmware || SourceOf("firmware", "other") != "" {
		t.Fatal("SourceOf")
	}
}
