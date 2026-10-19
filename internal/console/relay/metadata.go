// Package relay implements the split between the internet-facing gateway
// (DMZ) and the internal core:
//
//   - the gateway terminates the agents' mTLS and relays every allowed call,
//     as opaque frames, to the core; it holds no database credentials and no
//     CA private key;
//   - the core opens the connections to the gateway (LAN → DMZ), and on each
//     of them serves the agent API; the firewall needs no DMZ → LAN rule.
//
// The gateway forwards the verified client certificate chain and the peer
// address as metadata. The core trusts that metadata only on calls that came
// through a tunnel, and still verifies the chain itself.
package relay

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"

	"google.golang.org/grpc/metadata"
)

const (
	// Binary metadata (the "-bin" suffix makes gRPC base64 the values).
	mdClientCert = "x-openrmm-client-cert-bin" // leaf first, then intermediates
	mdPeer       = "x-openrmm-peer"
)

// forwardedMD builds the metadata the gateway attaches to a relayed call.
// It is always built from scratch: nothing sent by the agent is forwarded.
func forwardedMD(chain []*x509.Certificate, peer netip.Addr) metadata.MD {
	md := metadata.MD{}
	for _, c := range chain {
		md.Append(mdClientCert, string(c.Raw))
	}
	if peer.IsValid() {
		md.Set(mdPeer, peer.String())
	}
	return md
}

// Forwarded is what the core learns about a relayed call.
type Forwarded struct {
	Chain []*x509.Certificate // empty for unauthenticated calls (enrollment)
	Peer  netip.Addr
}

type relayedKey struct{}

// MarkRelayed records that ctx belongs to a call received through a tunnel.
// Only the core's tunnel server sets it.
func MarkRelayed(ctx context.Context) context.Context {
	return context.WithValue(ctx, relayedKey{}, true)
}

// IsRelayed reports whether ctx belongs to a call received through a tunnel.
func IsRelayed(ctx context.Context) bool {
	v, _ := ctx.Value(relayedKey{}).(bool)
	return v
}

// FromContext extracts the forwarded data of a relayed call. It returns an
// error when ctx is not relayed: direct callers can never supply it.
func FromContext(ctx context.Context) (Forwarded, error) {
	var f Forwarded
	if !IsRelayed(ctx) {
		return f, errors.New("not a relayed call")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	for _, raw := range md.Get(mdClientCert) {
		c, err := x509.ParseCertificate([]byte(raw))
		if err != nil {
			return f, errors.New("forwarded certificate unreadable")
		}
		f.Chain = append(f.Chain, c)
	}
	if len(f.Chain) > 4 {
		return f, errors.New("forwarded chain too long")
	}
	if v := md.Get(mdPeer); len(v) == 1 {
		if ip, err := netip.ParseAddr(v[0]); err == nil {
			f.Peer = ip
		}
	}
	return f, nil
}
