package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Window restricts a rule to days and hours, in the endpoint's local time.
// An End before Start crosses midnight (e.g. 22:00-05:00); the day is the
// one on which the window starts.
type Window struct {
	Days  []string `json:"days,omitempty"` // mon … sun; empty means every day
	Start string   `json:"start"`          // HH:MM
	End   string   `json:"end"`            // HH:MM
}

var weekdays = map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday}

func parseClock(s string) (int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil || len(s) != 5 {
		return 0, fmt.Errorf("invalid time %q (use HH:MM)", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

func (w *Window) validate() error {
	if len(w.Days) > 7 {
		return errors.New("window: at most 7 days")
	}
	seen := map[string]bool{}
	for _, d := range w.Days {
		if _, ok := weekdays[d]; !ok || seen[d] {
			return fmt.Errorf("window: invalid or repeated day %q (use mon, tue, wed, thu, fri, sat, sun)", d)
		}
		seen[d] = true
	}
	start, err := parseClock(w.Start)
	if err != nil {
		return fmt.Errorf("window: %w", err)
	}
	end, err := parseClock(w.End)
	if err != nil {
		return fmt.Errorf("window: %w", err)
	}
	if start == end {
		return errors.New("window: start and end must differ")
	}
	return nil
}

func (w *Window) onDay(d time.Weekday) bool {
	if len(w.Days) == 0 {
		return true
	}
	for _, s := range w.Days {
		if weekdays[s] == d {
			return true
		}
	}
	return false
}

// Contains reports whether t (local time of the endpoint) is inside the window.
func (w *Window) Contains(t time.Time) bool {
	if w == nil {
		return true
	}
	start, err1 := parseClock(w.Start)
	end, err2 := parseClock(w.End)
	if err1 != nil || err2 != nil {
		return false
	}
	m := t.Hour()*60 + t.Minute()
	if start < end {
		return m >= start && m < end && w.onDay(t.Weekday())
	}
	// Crosses midnight: the evening part belongs to today, the morning
	// part to the window that started yesterday.
	if m >= start {
		return w.onDay(t.Weekday())
	}
	return m < end && w.onDay(t.AddDate(0, 0, -1).Weekday())
}

// String renders the window for people.
func (w *Window) String() string {
	if w == nil {
		return ""
	}
	days := "ogni giorno"
	if len(w.Days) > 0 {
		days = strings.Join(w.Days, ",")
	}
	return days + " " + w.Start + "-" + w.End
}
