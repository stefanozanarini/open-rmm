package gateway

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/netip"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/pki"
)

// unauthenticatedMethods may be called without a client certificate.
var unauthenticatedMethods = map[string]bool{
	openrmmv1.EnrollmentService_Enroll_FullMethodName: true,
}

type identityKey struct{}

// AgentFromContext returns the authenticated agent of the call.
func AgentFromContext(ctx context.Context) (store.Agent, bool) {
	a, ok := ctx.Value(identityKey{}).(store.Agent)
	return a, ok
}

// authenticate verifies that the TLS peer presented an agent certificate that
// chains to the agents CA, carries a well-formed identity and belongs to an
// active agent whose current certificate it is.
func (s *Server) authenticate(ctx context.Context, method string) (context.Context, error) {
	if unauthenticatedMethods[method] {
		return ctx, nil
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	leaf := ti.State.VerifiedChains[0][0]
	if !hasClientAuth(leaf) {
		return nil, status.Error(codes.Unauthenticated, "certificate not valid for client auth")
	}
	id, err := pki.IdentityFromCert(leaf)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid agent identity")
	}
	a, err := s.store.GetAgent(ctx, id.TenantID, id.AgentID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Error(codes.PermissionDenied, "unknown agent")
	}
	if err != nil {
		s.log.Error("agent lookup failed", "err", err)
		return nil, status.Error(codes.Unavailable, "temporarily unavailable")
	}
	if a.Status != store.AgentActive {
		return nil, status.Error(codes.PermissionDenied, "agent revoked")
	}
	// Only the most recently issued certificate is accepted, so replacing a
	// certificate implicitly revokes the previous one.
	if pki.Fingerprint(leaf) != a.CertFingerprint {
		return nil, status.Error(codes.PermissionDenied, "certificate superseded")
	}
	return context.WithValue(ctx, identityKey{}, a), nil
}

func hasClientAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func (s *Server) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	ctx, err := s.authenticate(ctx, info.FullMethod)
	if err != nil {
		s.logDenied(ctx, info.FullMethod, err)
		return nil, err
	}
	return handler(ctx, req)
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

func (s *Server) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := s.authenticate(ss.Context(), info.FullMethod)
	if err != nil {
		s.logDenied(ss.Context(), info.FullMethod, err)
		return err
	}
	return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
}

func (s *Server) logDenied(ctx context.Context, method string, err error) {
	s.log.LogAttrs(ctx, slog.LevelWarn, "request denied",
		slog.String("method", method), slog.String("peer", peerIP(ctx).String()), slog.String("reason", status.Convert(err).Message()))
}

// peerIP returns the remote address of the call, or the zero Addr.
func peerIP(ctx context.Context) netip.Addr {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}
