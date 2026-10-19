package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
)

// frame is an opaque gRPC message: the gateway never decodes payloads.
type frame struct{ data []byte }

type rawCodec struct{}

func (rawCodec) Name() string { return "proto" } // same wire name: frames pass through unchanged

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	f, ok := v.(*frame)
	if !ok {
		return nil, errors.New("relay: unexpected message type")
	}
	return mem.BufferSlice{mem.SliceBuffer(f.data)}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	f, ok := v.(*frame)
	if !ok {
		return errors.New("relay: unexpected message type")
	}
	f.data = data.Materialize()
	return nil
}

var _ encoding.CodecV2 = rawCodec{}

// allowed lists what agents may reach through the gateway. Anything else
// (including future internal services on the core) is refused at the edge.
var allowed = map[string]bool{
	openrmmv1.EnrollmentService_Enroll_FullMethodName:      false, // false: no client certificate needed
	openrmmv1.AgentService_Connect_FullMethodName:          true,
	openrmmv1.AgentService_RenewCertificate_FullMethodName: true,
	openrmmv1.AgentService_GetModule_FullMethodName:        true,
	openrmmv1.AgentService_GetPackage_FullMethodName:       true,
	openrmmv1.AgentService_GetAgentRelease_FullMethodName:  true,
	openrmmv1.AgentService_Shell_FullMethodName:            true,
}

// Gateway is the DMZ side: it accepts agents and forwards their calls over
// the tunnels opened by the core.
type Gateway struct {
	tunnels *TunnelPool
	log     *slog.Logger
	conn    *grpc.ClientConn

	mu      sync.Mutex
	limiter map[netip.Addr]*rate.Limiter
}

// NewGateway returns a gateway forwarding to the core through pool.
func NewGateway(pool *TunnelPool, log *slog.Logger) (*Gateway, error) {
	conn, err := pool.ClientConn()
	if err != nil {
		return nil, err
	}
	g := &Gateway{tunnels: pool, log: log, conn: conn, limiter: map[netip.Addr]*rate.Limiter{}}
	go g.keepConnected()
	return g, nil
}

// keepConnected makes the gRPC client take up a tunnel as soon as one is
// available, instead of at the next agent call: an unused tunnel would
// otherwise wait for an HTTP/2 preface until the core gives up on it.
func (g *Gateway) keepConnected() {
	ctx := context.Background()
	for {
		st := g.conn.GetState()
		if st == connectivity.Shutdown {
			return
		}
		if st == connectivity.Idle {
			g.conn.Connect()
		}
		g.conn.WaitForStateChange(ctx, st)
	}
}

// Close releases the client side of the tunnels.
func (g *Gateway) Close() error { return g.conn.Close() }

// AgentServer builds the agent-facing gRPC server (TLS from tlsCfg).
func (g *Gateway) AgentServer(creds credentials.TransportCredentials) *grpc.Server {
	return grpc.NewServer(
		grpc.Creds(creds),
		grpc.ForceServerCodecV2(rawCodec{}),
		grpc.UnknownServiceHandler(g.handle),
		grpc.MaxRecvMsgSize(4<<20),
		grpc.MaxSendMsgSize(4<<20),
		grpc.MaxConcurrentStreams(16),
		grpc.ConnectionTimeout(10*time.Second),
	)
}

func (g *Gateway) allowEnroll(ip netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.limiter) > 50000 {
		g.limiter = map[netip.Addr]*rate.Limiter{}
	}
	l, ok := g.limiter[ip]
	if !ok {
		l = rate.NewLimiter(rate.Every(6*time.Second), 5)
		g.limiter[ip] = l
	}
	return l.Allow()
}

func (g *Gateway) handle(_ any, ss grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(ss)
	if !ok {
		return status.Error(codes.Internal, "no method")
	}
	needCert, known := allowed[method]
	if !known {
		return status.Error(codes.Unimplemented, "unknown method")
	}
	ctx := ss.Context()
	p, _ := peer.FromContext(ctx)
	var ip netip.Addr
	if p != nil && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			ip, _ = netip.ParseAddr(host)
			ip = ip.Unmap()
		}
	}
	var md metadata.MD
	if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.VerifiedChains) > 0 {
		md = forwardedMD(ti.State.VerifiedChains[0][:len(ti.State.VerifiedChains[0])-1], ip)
	} else {
		if needCert {
			return status.Error(codes.Unauthenticated, "client certificate required")
		}
		md = forwardedMD(nil, ip)
	}
	if !needCert && !g.allowEnroll(ip) {
		return status.Error(codes.ResourceExhausted, "too many enrollment attempts")
	}
	octx, cancel := context.WithCancel(metadata.NewOutgoingContext(ctx, md))
	defer cancel()
	cs, err := g.conn.NewStream(octx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, method,
		grpc.ForceCodecV2(rawCodec{}))
	if err != nil {
		return status.Error(codes.Unavailable, "console unavailable")
	}
	// Agent → core.
	upErr := make(chan error, 1)
	go func() {
		for {
			f := &frame{}
			if err := ss.RecvMsg(f); err != nil {
				if errors.Is(err, io.EOF) {
					upErr <- cs.CloseSend()
					return
				}
				upErr <- err
				return
			}
			if err := cs.SendMsg(f); err != nil {
				upErr <- err
				return
			}
		}
	}()
	// Core → agent.
	if hdr, err := cs.Header(); err == nil {
		_ = ss.SendHeader(hdr)
	}
	for {
		f := &frame{}
		err := cs.RecvMsg(f)
		if errors.Is(err, io.EOF) {
			ss.SetTrailer(cs.Trailer())
			return nil
		}
		if err != nil {
			ss.SetTrailer(cs.Trailer())
			return err // status from the core, passed through
		}
		if err := ss.SendMsg(f); err != nil {
			cancel()
			return err
		}
		select {
		case err := <-upErr:
			if err != nil {
				cancel()
				return err
			}
			upErr = nil // closed cleanly; keep reading the responses
		default:
		}
	}
}

// TunnelsUp reports how many tunnels from the core are connected.
func (g *Gateway) TunnelsUp() int { return g.tunnels.Len() }
