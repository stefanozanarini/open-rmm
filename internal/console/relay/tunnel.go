package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/stefanozanarini/open-rmm/internal/pki"
)

const handshakeTimeout = 10 * time.Second

// TunnelPool is the gateway side: it accepts the tunnels opened by the core
// and hands them to the gRPC client that forwards agent calls.
type TunnelPool struct {
	log   *slog.Logger
	conns chan net.Conn
	mu    sync.Mutex
	live  int
}

// NewTunnelPool returns an empty pool.
func NewTunnelPool(log *slog.Logger) *TunnelPool {
	return &TunnelPool{log: log, conns: make(chan net.Conn, 16)}
}

// Len returns the number of tunnels currently connected.
func (p *TunnelPool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.live
}

// TunnelTLS is the gateway's TLS configuration for the tunnel listener:
// the client must present a core certificate issued by the agents CA.
func TunnelTLS(cert tls.Certificate, agentsCA *x509.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(agentsCA)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || !pki.IsCore(cs.VerifiedChains[0][0]) {
				return errors.New("tunnel client is not an open-rmm core")
			}
			return nil
		},
	}
}

// Serve accepts tunnels on lis (already TLS-wrapped with TunnelTLS).
func (p *TunnelPool) Serve(ctx context.Context, lis net.Listener) error {
	go func() { <-ctx.Done(); _ = lis.Close() }()
	for {
		c, err := lis.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go p.admit(ctx, c)
	}
}

func (p *TunnelPool) admit(ctx context.Context, c net.Conn) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		_ = c.Close()
		return
	}
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		p.log.Warn("tunnel refused", "peer", c.RemoteAddr().String(), "err", err)
		_ = c.Close()
		return
	}
	p.log.Info("tunnel from core accepted", "peer", c.RemoteAddr().String())
	select {
	case p.conns <- &countedConn{Conn: c, pool: p}:
		p.mu.Lock()
		p.live++
		p.mu.Unlock()
	default:
		p.log.Warn("too many idle tunnels, closing one")
		_ = c.Close()
	}
}

// countedConn decrements the live counter once, on close.
type countedConn struct {
	net.Conn
	pool *TunnelPool
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() {
		c.pool.mu.Lock()
		c.pool.live--
		c.pool.mu.Unlock()
	})
	return c.Conn.Close()
}

// ClientConn returns a gRPC client whose transports are the tunnels: each
// time it needs a connection it takes the next tunnel opened by the core.
func (p *TunnelPool) ClientConn() (*grpc.ClientConn, error) {
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		select {
		case c := <-p.conns:
			return c, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("no tunnel from the core: %w", ctx.Err())
		}
	}
	return grpc.NewClient("passthrough:///core",
		grpc.WithContextDialer(dial),
		// The tunnel is already mutually authenticated TLS.
		grpc.WithTransportCredentials(insecure.NewCredentials()), // #nosec G402 -- inside the mTLS tunnel
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4<<20), grpc.MaxCallSendMsgSize(4<<20)),
	)
}

// Dialer is the core side: it keeps a tunnel open to the gateway and
// exposes it as a net.Listener for the core's gRPC server. One tunnel at a
// time: the gateway's gRPC client uses one transport, and a spare tunnel
// would sit idle waiting for an HTTP/2 preface that never comes. A broken
// tunnel is reopened within seconds (and detected by keepalives).
type Dialer struct {
	Target string // gateway tunnel address, host:port
	TLS    *tls.Config
	Count  int // tunnels to keep open, default 1
	Log    *slog.Logger
	Peer   string // what the tunnels lead to, for the logs (default "gateway")

	accept chan net.Conn
	done   chan struct{}
	once   sync.Once
	up     atomic.Int32
}

// Up returns the number of tunnels currently open.
func (d *Dialer) Up() int { return int(d.up.Load()) }

// CoreTLS is the core's TLS configuration for dialing the gateway: it
// presents the core certificate and trusts only the open-rmm root.
func CoreTLS(serverName string, root *x509.Certificate, cert tls.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: pool, Certificates: []tls.Certificate{cert}}
}

func (d *Dialer) init() {
	d.once.Do(func() {
		d.accept = make(chan net.Conn)
		d.done = make(chan struct{})
		if d.Count <= 0 {
			d.Count = 1
		}
		if d.Peer == "" {
			d.Peer = "gateway"
		}
	})
}

// Run keeps the tunnels open until ctx ends.
func (d *Dialer) Run(ctx context.Context) {
	d.init()
	var wg sync.WaitGroup
	for i := range d.Count {
		wg.Add(1)
		go func() { defer wg.Done(); d.keep(ctx, i) }()
	}
	wg.Wait()
	_ = d.Close()
}

func (d *Dialer) keep(ctx context.Context, slot int) {
	backoff := time.Second
	for ctx.Err() == nil {
		dctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		c, err := (&tls.Dialer{Config: d.TLS}).DialContext(dctx, "tcp", d.Target)
		cancel()
		if err != nil {
			d.Log.Warn("tunnel failed", "peer", d.Peer, "slot", slot, "addr", d.Target, "err", err)
			wait := backoff/2 + rand.N(backoff/2+1) // #nosec G404 -- jitter, not a secret
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		d.up.Add(1)
		closed := make(chan struct{})
		tc := &notifyConn{Conn: c, closed: closed}
		select {
		case d.accept <- tc:
		case <-ctx.Done():
			_ = c.Close()
			return
		}
		d.Log.Info("tunnel open", "peer", d.Peer, "slot", slot, "addr", d.Target)
		select {
		case <-closed:
			d.up.Add(-1)
			d.Log.Warn("tunnel closed, reopening", "peer", d.Peer, "slot", slot)
		case <-ctx.Done():
			d.up.Add(-1)
			_ = c.Close()
			return
		}
	}
}

type notifyConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// Accept implements net.Listener: the "accepted" connections are the
// tunnels the core dialed.
func (d *Dialer) Accept() (net.Conn, error) {
	d.init()
	select {
	case c := <-d.accept:
		return c, nil
	case <-d.done:
		return nil, net.ErrClosed
	}
}

// Close implements net.Listener.
func (d *Dialer) Close() error {
	d.init()
	select {
	case <-d.done:
	default:
		close(d.done)
	}
	return nil
}

// Addr implements net.Listener.
func (d *Dialer) Addr() net.Addr { return tunnelAddr(d.Target) }

type tunnelAddr string

func (a tunnelAddr) Network() string { return "tunnel" }
func (a tunnelAddr) String() string  { return string(a) }
