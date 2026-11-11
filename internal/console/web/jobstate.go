package web

import (
	"encoding/json"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
)

// A job that installs several items (Windows updates, winget applications)
// succeeds when the module ran, even if some items failed: the module
// lists them in its result. The console shows such a job as "partial".

// jobFailures counts the items a succeeded job reports as failed: the
// entries of "installed" or "upgraded" with ok false, or with a Windows
// Update result other than succeeded.
func jobFailures(j store.Job) int {
	if j.State != store.JobSucceeded || len(j.Result) == 0 {
		return 0
	}
	var r struct {
		Installed []json.RawMessage `json:"installed"`
		Upgraded  []json.RawMessage `json:"upgraded"`
	}
	if json.Unmarshal(j.Result, &r) != nil {
		return 0
	}
	n := 0
	for _, raw := range append(r.Installed, r.Upgraded...) {
		var it struct {
			OK     *bool  `json:"ok"`
			Result string `json:"result"`
		}
		if json.Unmarshal(raw, &it) != nil {
			continue
		}
		switch {
		case it.OK != nil:
			if !*it.OK {
				n++
			}
		case it.Result != "" && it.Result != "succeeded" && it.Result != "succeeded_with_errors":
			n++
		}
	}
	return n
}

// jobState is the state shown for a job: partial for a succeeded job with
// failed items.
func jobState(j store.Job) string {
	if jobFailures(j) > 0 {
		return "partial"
	}
	return string(j.State)
}
