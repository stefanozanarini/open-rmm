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
	"net/http"
	"sync"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/relay"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
)

// clientTLS is the customer console's TLS configuration for the link: its
// own certificate, and the central console's pinned one. The central
// certificate is self-signed, so chain verification is replaced by the pin.
func clientTLS(id *Identity, centralFP string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{id.Cert},
		InsecureSkipVerify: true, // #nosec G402 -- replaced by the pinned fingerprint in VerifyConnection
		VerifyConnection:   pinned(centralFP),
	}
}

// Join enrolls this console with a central console using a pasted bundle,
// and returns the uplink to store.
func Join(ctx context.Context, bundle, by string, now time.Time) (store.Uplink, error) {
	b, err := ParseBundle(bundle)
	if err != nil {
		return store.Uplink{}, err
	}
	id, err := NewIdentity("customer", now)
	if err != nil {
		return store.Uplink{}, err
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{Config: clientTLS(id, b.Fingerprint)}).DialContext(dctx, "tcp", b.Addr)
	if err != nil {
		return store.Uplink{}, errorf("cannot reach the central console at %s: %w", b.Addr, err)
	}
	defer conn.Close()
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	body, _ := json.Marshal(enrollRequest{Token: b.Token})
	req, err := http.NewRequest(http.MethodPost, "http://central"+pathEnroll, bytes.NewReader(body))
	if err != nil {
		return store.Uplink{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(conn); err != nil {
		return store.Uplink{}, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return store.Uplink{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return store.Uplink{}, errorf("the central console refused the link token (HTTP %d)", resp.StatusCode)
	}
	var out enrollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&out); err != nil || out.LinkID == "" {
		return store.Uplink{}, errorf("unexpected enrollment response")
	}
	return store.Uplink{LinkID: out.LinkID, CentralAddr: b.Addr, CentralFingerprint: b.Fingerprint,
		CertPEM: id.CertPEM, KeyPEM: id.KeyPEM, CreatedBy: by}, nil
}

// Uplink keeps the customer side of the link running: while a link is
// stored and not suspended, it keeps tunnels open to the central console
// and serves Handler on them. Suspending or removing the link closes them
// within Poll.
type Uplink struct {
	Store   store.FederationStore
	Handler http.Handler
	Log     *slog.Logger
	Poll    time.Duration // default 15s

	mu      sync.Mutex
	running string // link id being served
	cancel  context.CancelFunc
	srv     *http.Server
	dialer  *relay.Dialer
}

// Run applies the stored link state until ctx ends.
func (u *Uplink) Run(ctx context.Context) {
	poll := u.Poll
	if poll <= 0 {
		poll = 15 * time.Second
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		u.Sync(ctx)
		select {
		case <-ctx.Done():
			u.stop()
			return
		case <-t.C:
		}
	}
}

// Sync starts or stops the tunnels to match the stored link now.
func (u *Uplink) Sync(ctx context.Context) {
	l, err := u.Store.GetUplink(ctx)
	want := ""
	if err == nil && !l.Suspended {
		want = l.LinkID + "|" + l.CentralAddr + "|" + l.CentralFingerprint
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		u.Log.Warn("federation link state unreadable", "err", err)
		return
	}
	u.mu.Lock()
	same := u.running == want
	u.mu.Unlock()
	if same {
		return
	}
	u.stop()
	if want == "" {
		return
	}
	id, err := LoadIdentity(l.CertPEM, l.KeyPEM)
	if err != nil {
		u.Log.Error("federation identity unreadable", "err", err)
		return
	}
	rctx, cancel := context.WithCancel(ctx)
	d := &relay.Dialer{Target: l.CentralAddr, TLS: clientTLS(id, l.CentralFingerprint), Count: tunnelsPerLink,
		Log: u.Log, Peer: "central console"}
	srv := &http.Server{Handler: u.Handler, ReadHeaderTimeout: 30 * time.Second}
	go d.Run(rctx)
	go func() {
		if err := srv.Serve(d); err != nil && !errors.Is(err, http.ErrServerClosed) {
			u.Log.Warn("federation server stopped", "err", err)
		}
	}()
	u.mu.Lock()
	u.running, u.cancel, u.srv, u.dialer = want, cancel, srv, d
	u.mu.Unlock()
	u.Log.Info("federation link started", "link", l.LinkID, "central", l.CentralAddr)
}

// Up returns the number of tunnels open.
func (u *Uplink) Up() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.dialer == nil {
		return 0
	}
	return u.dialer.Up()
}

func (u *Uplink) stop() {
	u.mu.Lock()
	cancel, srv := u.cancel, u.srv
	u.running, u.cancel, u.srv, u.dialer = "", nil, nil, nil
	u.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	// Close, not Shutdown: a suspended link must end at once.
	_ = srv.Close()
	u.Log.Info("federation link stopped")
}
