package web

import (
	"testing"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
)

func TestJobState(t *testing.T) {
	for result, want := range map[string]string{
		``: "succeeded",
		`{"installed":[{"result":"succeeded"},{"result":"succeeded_with_errors"}]}`:         "succeeded",
		`{"installed":[{"result":"succeeded"},{"result":"failed","hresult":"0x800F0983"}]}`: "partial",
		`{"installed":[{"result":"download_failed"}]}`:                                      "partial",
		`{"upgraded":[{"id":"7zip.7zip","ok":true}]}`:                                       "succeeded",
		`{"installed":[{"id":"Google.Chrome","ok":false}]}`:                                 "partial",
		`{"installed":"text"}`: "succeeded",
	} {
		if got := jobState(store.Job{State: store.JobSucceeded, Result: []byte(result)}); got != want {
			t.Errorf("%s: %s, want %s", result, got, want)
		}
	}
	if got := jobState(store.Job{State: store.JobFailed, Result: []byte(`{"installed":[{"ok":false}]}`)}); got != "failed" {
		t.Errorf("failed job: %s", got)
	}
}
