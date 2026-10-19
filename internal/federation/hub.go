package federation

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/store"
)

const (
	handshakeTimeout = 10 * time.Second
	// Tunnels kept per link: concurrent requests to one customer console.
	tunnelsPerLink = 4
	summaryEvery   = 5 * time.Minute
)

// identityName is the console_keys entry of the central link certificate.
const identityName = "federation-central"

// CentralIdentity loads the central console's link certificate, creating it
// on first use.
func CentralIdentity(ctx context.Context, st store.FederationStore, now time.Time) (*Identity, error) {
	c, k, err := st.GetConsoleKey(ctx, identityName)
	if errors.Is(err, store.ErrNotFound) {
		id, err := NewIdentity("central", now)
		if err != nil {
			return nil, err
		}
		if c, k, err = st.PutConsoleKey(ctx, identityName, id.CertPEM, id.KeyPEM); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return LoadIdentity(c, k)
}

// Hub is the central side: it accepts the tunnels of the linked consoles
// and gives an HTTP client per link that sends requests over them.
type Hub struct {
	Store store.FederationStore
	ID    *Identity
	Log   *slog.Logger
	Now   func() time.Time
	// DialWait is how long a request waits for a tunnel (default 10s: a
	// linked console reconnects within seconds after a restart).
	DialWait time.Duration

	mu      sync.Mutex
	pools   map[string]chan net.Conn
	live    map[string]int
	clients map[string]*http.Client
}

func (h *Hub) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Hub) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{h.ID.Cert},
		// Customer consoles are known by their certificate fingerprint,
		// checked after the handshake against the links.
		ClientAuth: tls.RequireAnyClientCert,
	}
}

// Serve accepts link connections on lis (plain TCP) until ctx ends.
func (h *Hub) Serve(ctx context.Context, lis net.Listener) error {
	go func() { <-ctx.Done(); _ = lis.Close() }()
	cfg := h.tlsConfig()
	for {
		c, err := lis.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go h.admit(ctx, tls.Server(c, cfg))
	}
}

func (h *Hub) admit(ctx context.Context, tc *tls.Conn) {
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		h.Log.Warn("federation link refused", "peer", tc.RemoteAddr().String(), "err", err)
		_ = tc.Close()
		return
	}
	fp := Fingerprint(tc.ConnectionState().PeerCertificates[0].Raw)
	link, err := h.Store.LinkByFingerprint(ctx, fp)
	switch {
	case err == nil && link.Status == store.LinkActive:
		h.add(ctx, link, tc)
	case errors.Is(err, store.ErrNotFound):
		h.enroll(ctx, tc, fp)
	default:
		h.Log.Warn("federation link refused", "peer", tc.RemoteAddr().String(), "link", link.ID, "status", link.Status, "err", err)
		_ = tc.Close()
	}
}

// add puts a tunnel of an active link in its pool.
func (h *Hub) add(ctx context.Context, link store.FederationLink, c net.Conn) {
	h.mu.Lock()
	if h.pools == nil {
		h.pools, h.live, h.clients = map[string]chan net.Conn{}, map[string]int{}, map[string]*http.Client{}
	}
	pool, ok := h.pools[link.ID]
	if !ok {
		pool = make(chan net.Conn, tunnelsPerLink*2)
		h.pools[link.ID] = pool
	}
	h.mu.Unlock()
	lc := &linkConn{Conn: c, hub: h, link: link.ID}
	h.mu.Lock()
	h.live[link.ID]++
	h.mu.Unlock()
	lc.watch()
	select {
	case pool <- lc:
		_ = h.Store.TouchLink(ctx, link.ID, h.now(), nil)
		h.Log.Info("federation tunnel accepted", "link", link.ID, "name", link.Name)
	default:
		_ = lc.Close()
	}
}

// linkConn decrements the live counter once, on close. While it waits in
// the pool it is watched, so a tunnel closed by the customer console (link
// suspended, restart) is noticed at once: the customer only ever answers,
// so any read result before a request means the tunnel is gone.
type linkConn struct {
	net.Conn
	hub      *Hub
	link     string
	once     sync.Once
	watching chan struct{} // closed when the watcher returns
	dead     atomicBool
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (b *atomicBool) set()      { b.mu.Lock(); b.v = true; b.mu.Unlock() }
func (b *atomicBool) get() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.v }

func (c *linkConn) watch() {
	c.watching = make(chan struct{})
	go func() {
		defer close(c.watching)
		var b [1]byte
		_, err := c.Conn.Read(b[:])
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return // claimed for a request
		}
		c.dead.set()
		_ = c.Close()
	}()
}

// claim stops the watcher before the connection carries a request; false
// if the tunnel is gone.
func (c *linkConn) claim() bool {
	_ = c.Conn.SetReadDeadline(time.Now())
	<-c.watching
	_ = c.Conn.SetReadDeadline(time.Time{})
	return !c.dead.get()
}

func (c *linkConn) Close() error {
	c.once.Do(func() {
		c.hub.mu.Lock()
		c.hub.live[c.link]--
		c.hub.mu.Unlock()
	})
	return c.Conn.Close()
}

type enrollRequest struct {
	Token string `json:"token"`
}

type enrollResponse struct {
	LinkID string `json:"link_id"`
	Name   string `json:"name"`
}

// enroll serves one enrollment request from an unknown certificate.
func (h *Hub) enroll(ctx context.Context, tc *tls.Conn, fp string) {
	defer tc.Close()
	_ = tc.SetDeadline(h.now().Add(handshakeTimeout))
	req, err := http.ReadRequest(bufio.NewReader(tc))
	if err != nil || req.Method != http.MethodPost || req.URL.Path != pathEnroll {
		h.Log.Warn("federation: unknown certificate", "peer", tc.RemoteAddr().String())
		return
	}
	reply := func(code int, v any) {
		body, _ := json.Marshal(v)
		resp := &http.Response{StatusCode: code, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": {"application/json"}},
			ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body)), Close: true}
		_ = resp.Write(tc)
	}
	var in enrollRequest
	if err := json.NewDecoder(io.LimitReader(req.Body, 4<<10)).Decode(&in); err != nil || in.Token == "" {
		reply(http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	link, err := h.Store.EnrollLink(ctx, store.HashToken(in.Token), fp, h.now())
	if err != nil {
		h.Log.Warn("federation enrollment refused", "peer", tc.RemoteAddr().String(), "err", err)
		reply(http.StatusForbidden, map[string]string{"error": "link token invalid, expired or already used"})
		return
	}
	h.Log.Info("federation link enrolled", "link", link.ID, "name", link.Name, "fingerprint", fp, "peer", tc.RemoteAddr().String())
	reply(http.StatusOK, enrollResponse{LinkID: link.ID, Name: link.Name})
}

// Connected returns the number of tunnels open for a link.
func (h *Hub) Connected(linkID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.live[linkID]
}

// Client returns the HTTP client whose connections are the link's tunnels.
func (h *Hub) Client(linkID string) *http.Client {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pools == nil {
		h.pools, h.live, h.clients = map[string]chan net.Conn{}, map[string]int{}, map[string]*http.Client{}
	}
	if c, ok := h.clients[linkID]; ok {
		return c
	}
	pool, ok := h.pools[linkID]
	if !ok {
		pool = make(chan net.Conn, tunnelsPerLink*2)
		h.pools[linkID] = pool
	}
	wait := h.DialWait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		t := time.NewTimer(wait)
		defer t.Stop()
		for {
			select {
			case c := <-pool:
				if lc, ok := c.(*linkConn); ok && !lc.claim() {
					continue
				}
				return c, nil
			case <-t.C:
				return nil, ErrOffline
			case <-ctx.Done():
				return nil, ErrOffline
			}
		}
	}
	c := &http.Client{
		Transport: &http.Transport{DialContext: dial, MaxConnsPerHost: tunnelsPerLink, MaxIdleConnsPerHost: tunnelsPerLink,
			ResponseHeaderTimeout: 60 * time.Second, DisableCompression: true},
		// Redirects go back to the browser.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	h.clients[linkID] = c
	return c
}

// ErrOffline is returned when a linked console has no tunnel open.
var ErrOffline = errors.New("the linked console is not connected")

// Drop closes the tunnels of a link (after revocation).
func (h *Hub) Drop(linkID string) {
	h.mu.Lock()
	pool := h.pools[linkID]
	c := h.clients[linkID]
	delete(h.clients, linkID)
	h.mu.Unlock()
	if c != nil {
		c.CloseIdleConnections()
	}
	for pool != nil {
		select {
		case conn := <-pool:
			_ = conn.Close()
		default:
			return
		}
	}
}

// URL is the base URL of requests sent over a link's client.
const URL = "http://linked-console"

// RunSummaries fetches the summary of every connected link periodically.
func (h *Hub) RunSummaries(ctx context.Context) {
	t := time.NewTicker(summaryEvery)
	defer t.Stop()
	for {
		h.mu.Lock()
		var links []string
		for id, n := range h.live {
			if n > 0 {
				links = append(links, id)
			}
		}
		h.mu.Unlock()
		for _, id := range links {
			if err := h.FetchSummary(ctx, id); err != nil {
				h.Log.Warn("federation summary failed", "link", id, "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// FetchSummary asks a linked console for its summary and stores it.
func (h *Hub) FetchSummary(ctx context.Context, linkID string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL+PathSummary, nil)
	if err != nil {
		return err
	}
	resp, err := h.Client(linkID).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errorf("summary: HTTP %d", resp.StatusCode)
	}
	var s Summary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&s); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return h.Store.TouchLink(ctx, linkID, h.now(), raw)
}
