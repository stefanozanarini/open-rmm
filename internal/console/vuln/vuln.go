// Package vuln finds the CVEs that affect the endpoints: Windows from the
// Microsoft security updates (MSRC), compared with each agent's build;
// known applications from NVD, compared with the installed version; Linux
// from the security updates the osupdate module reports. CISA's Known
// Exploited Vulnerabilities catalog marks the CVEs exploited in the wild.
//
// The console downloads the sources in the background (Refresh) and keeps
// compact extracts in the store; matching is local and fast.
package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
)

// CVE is a vulnerability in the extracts.
type CVE struct {
	ID        string    `json:"id"`
	Title     string    `json:"title,omitempty"`
	CVSS      float64   `json:"cvss,omitempty"`
	Severity  string    `json:"severity,omitempty"` // Critical, High/Important, Medium/Moderate, Low
	Exploited bool      `json:"exploited,omitempty"`
	Released  time.Time `json:"released,omitempty"`
	// Fixes: Windows builds that fix it (MSRC).
	Fixes []WinFix `json:"fixes,omitempty"`
}

// WinFix is a Windows build fixing a CVE: 10.0.<Build>.<Rev>, from KB.
type WinFix struct {
	Build int    `json:"b"`
	Rev   int    `json:"r"`
	KB    string `json:"kb,omitempty"`
}

// Store keeps the extracts.
type Store interface {
	PutVulnFeed(ctx context.Context, f store.VulnFeed) error
	GetVulnFeed(ctx context.Context, key string) (store.VulnFeed, error)
	ListVulnFeeds(ctx context.Context, prefix string) ([]store.VulnFeed, error)
}

// Fetcher downloads the sources.
type Fetcher struct {
	Store  Store
	Client *http.Client
	Log    *slog.Logger
	Now    func() time.Time
	// Base URLs, replaced by tests.
	MSRC, KEV string
	// Months of Microsoft updates kept.
	Months int
}

// NewFetcher returns a fetcher of the public sources.
func NewFetcher(st Store, log *slog.Logger) *Fetcher {
	return &Fetcher{Store: st, Client: &http.Client{Timeout: 10 * time.Minute}, Log: log, Now: time.Now,
		MSRC: "https://api.msrc.microsoft.com/cvrf/v3.0", Months: 24,
		KEV: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}
}

// Refresh downloads what is missing or changed. Errors of one source do not
// stop the others; the first is returned.
func (f *Fetcher) Refresh(ctx context.Context) error {
	var first error
	for _, step := range []struct {
		name string
		run  func(context.Context) error
	}{{"kev", f.refreshKEV}, {"msrc", f.refreshMSRC}} {
		if err := step.run(ctx); err != nil {
			f.Log.Warn("vulnerability source", "source", step.name, "err", err)
			if first == nil {
				first = fmt.Errorf("%s: %w", step.name, err)
			}
		}
	}
	return first
}

// get downloads url as JSON into v.
func (f *Fetcher) get(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "open-rmm")
	resp, err := f.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 512<<20)).Decode(v)
}

// fresh tells whether the feed key was fetched within maxAge.
func (f *Fetcher) fresh(ctx context.Context, key string, maxAge time.Duration) bool {
	cur, err := f.Store.GetVulnFeed(ctx, key)
	return err == nil && f.Now().Sub(cur.FetchedAt) < maxAge
}

func (f *Fetcher) put(ctx context.Context, key, version string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return f.Store.PutVulnFeed(ctx, store.VulnFeed{Key: key, Version: version, Data: b})
}

// ErrNoData: no source downloaded yet.
var ErrNoData = errors.New("vulnerability data not downloaded yet")
