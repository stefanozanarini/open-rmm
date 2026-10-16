package gateway

import "time"

// SetCheckIntervalForTest changes how often open sessions re-check the agent
// status and returns a function restoring the previous value. Tests only.
func SetCheckIntervalForTest(d time.Duration) (restore func()) {
	old := seenWriteInterval
	seenWriteInterval = d
	return func() { seenWriteInterval = old }
}
