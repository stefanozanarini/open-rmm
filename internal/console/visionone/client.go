// Package visionone reads endpoint status and Workbench alerts from Trend
// Vision One (API v3) and turns them into checks and alerts.
//
// The connector is read-only: the API key needs only the "view" permissions
// for Endpoint Inventory and Workbench.
package visionone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Regions maps a region code to its API base URL.
var Regions = map[string]string{
	"eu": "https://api.eu.xdr.trendmicro.com", // European Union (Frankfurt)
	"us": "https://api.xdr.trendmicro.com",
	"uk": "https://api.uk.xdr.trendmicro.com",
	"au": "https://api.au.xdr.trendmicro.com",
	"sg": "https://api.sg.xdr.trendmicro.com",
	"in": "https://api.in.xdr.trendmicro.com",
	"jp": "https://api.xdr.trendmicro.co.jp",
	"me": "https://api.mea.xdr.trendmicro.com",
}

const (
	maxPages     = 100
	maxBody      = 16 << 20
	pageSize     = 1000
	alertsPerReq = 200
)

// Client calls the Vision One API.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// NewClient returns a client for a region code or an https base URL.
func NewClient(region, token string, hc *http.Client) (*Client, error) {
	raw := region
	if b, ok := Regions[strings.ToLower(region)]; ok {
		raw = b
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Scheme != "https" {
		return nil, fmt.Errorf("vision one: unknown region or invalid URL %q", region)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("vision one: empty API key")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{base: u, token: token, http: hc}, nil
}

// EPPAgent is the endpoint protection agent as seen by Vision One.
type EPPAgent struct {
	Status                string `json:"status"`
	Version               string `json:"version"`
	LastConnectedDateTime string `json:"lastConnectedDateTime"`
	ComponentUpdateStatus string `json:"componentUpdateStatus"`
	ProtectionManager     string `json:"protectionManager"`
	PolicyName            string `json:"policyName"`
}

// EDRSensor is the endpoint sensor as seen by Vision One.
type EDRSensor struct {
	Status                string `json:"status"`
	Connectivity          string `json:"connectivity"`
	Version               string `json:"version"`
	LastConnectedDateTime string `json:"lastConnectedDateTime"`
}

// Endpoint is one entry of the endpoint inventory.
type Endpoint struct {
	AgentGUID    string     `json:"agentGuid"`
	EndpointName string     `json:"endpointName"`
	OSName       string     `json:"osName"`
	EPPAgent     *EPPAgent  `json:"eppAgent"`
	EDRSensor    *EDRSensor `json:"edrSensor"`
}

// Entity is an entity in a Workbench alert's impact scope.
type Entity struct {
	EntityType  string          `json:"entityType"`
	EntityValue json.RawMessage `json:"entityValue"`
}

// Alert is a Workbench alert.
type Alert struct {
	ID              string `json:"id"`
	Model           string `json:"model"`
	Severity        string `json:"severity"`
	Score           int    `json:"score"`
	CreatedDateTime string `json:"createdDateTime"`
	Status          string `json:"status"`
	WorkbenchLink   string `json:"workbenchLink"`
	ImpactScope     struct {
		Entities []Entity `json:"entities"`
	} `json:"impactScope"`
}

// Hosts returns the host names in the alert's impact scope.
func (a Alert) Hosts() []string {
	var out []string
	for _, e := range a.ImpactScope.Entities {
		if !strings.EqualFold(e.EntityType, "host") {
			continue
		}
		var v struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(e.EntityValue, &v) == nil && v.Name != "" {
			out = append(out, v.Name)
		}
	}
	return out
}

type page[T any] struct {
	Items    []T    `json:"items"`
	NextLink string `json:"nextLink"`
}

// get follows nextLink pages, only on the configured host.
func getAll[T any](ctx context.Context, c *Client, path string, q url.Values) ([]T, error) {
	u := c.base.JoinPath(path)
	u.RawQuery = q.Encode()
	next := u.String()
	var out []T
	for i := 0; next != "" && i < maxPages; i++ {
		nu, err := url.Parse(next)
		if err != nil || nu.Host != c.base.Host || nu.Scheme != c.base.Scheme {
			return nil, fmt.Errorf("vision one: unexpected next link %q", next)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nu.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("vision one: %s %s: %s", path, resp.Status, strings.TrimSpace(string(body[:min(len(body), 300)])))
		}
		var p page[T]
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("vision one: %s: %w", path, err)
		}
		out = append(out, p.Items...)
		next = p.NextLink
	}
	return out, nil
}

// Endpoints lists the endpoint inventory.
func (c *Client) Endpoints(ctx context.Context) ([]Endpoint, error) {
	return getAll[Endpoint](ctx, c, "/v3.0/endpointSecurity/endpoints", url.Values{"top": {fmt.Sprint(pageSize)}})
}

// Alerts lists the Workbench alerts created in [since, until).
func (c *Client) Alerts(ctx context.Context, since, until time.Time) ([]Alert, error) {
	return getAll[Alert](ctx, c, "/v3.0/workbench/alerts", url.Values{
		"startDateTime":  {since.UTC().Format(time.RFC3339)},
		"endDateTime":    {until.UTC().Format(time.RFC3339)},
		"dateTimeTarget": {"createdDateTime"},
		"orderBy":        {"createdDateTime desc"},
		"top":            {fmt.Sprint(alertsPerReq)},
	})
}
