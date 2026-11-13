package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
)

// pkgServer serves a package in chunks of 1000 bytes.
type pkgServer struct {
	openrmmv1.UnimplementedAgentServiceServer
	content []byte
	cutAt   int  // stop with Unavailable after this many bytes of the call (0: never)
	legacy  bool // ignore the offset, like a console before resuming
	offsets []int64
}

func (p *pkgServer) GetPackage(req *openrmmv1.GetPackageRequest, stream openrmmv1.AgentService_GetPackageServer) error {
	p.offsets = append(p.offsets, req.GetOffset())
	off := req.GetOffset()
	if p.legacy {
		off = 0
	}
	sent := 0
	for i := off; i < int64(len(p.content)); i += 1000 {
		if p.cutAt > 0 && sent >= p.cutAt {
			return status.Error(codes.Unavailable, "connection reset")
		}
		end := min(i+1000, int64(len(p.content)))
		chunk := &openrmmv1.PackageChunk{Data: p.content[i:end]}
		if i == off && !p.legacy {
			chunk.Offset = off
		}
		if err := stream.Send(chunk); err != nil {
			return err
		}
		sent += int(end - i)
	}
	return nil
}

func pkgSession(t *testing.T, srv *pkgServer) *session {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	openrmmv1.RegisterAgentServiceServer(g, srv)
	go g.Serve(lis)
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &session{conn: conn}
}

func TestFetchPackageResumes(t *testing.T) {
	content := []byte(strings.Repeat("installer bytes ", 1000))
	sum := sha256.Sum256(content)
	ref := &openrmmv1.PackageRef{Sha256: sum[:], FileName: "setup.msi", Size: int64(len(content))}
	srv := &pkgServer{content: content, cutAt: 5000}
	s := pkgSession(t, srv)
	dest := filepath.Join(t.TempDir(), "setup.msi")

	err := s.FetchPackage(context.Background(), "job", ref, dest)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("interrupted download: %v", err)
	}
	if fi, err := os.Stat(dest); err != nil || fi.Size() != 5000 {
		t.Fatalf("partial file not kept: %v %v", fi, err)
	}
	srv.cutAt = 0
	if err := s.FetchPackage(context.Background(), "job", ref, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); !bytes.Equal(got, content) {
		t.Fatal("resumed file differs")
	}
	if len(srv.offsets) != 2 || srv.offsets[1] != 5000 {
		t.Fatalf("offsets: %v", srv.offsets)
	}

	// A console that cannot resume sends the whole package again.
	legacy := &pkgServer{content: content, legacy: true}
	dest2 := filepath.Join(t.TempDir(), "setup.msi")
	os.WriteFile(dest2, content[:3000], 0o600)
	if err := pkgSession(t, legacy).FetchPackage(context.Background(), "job", ref, dest2); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest2); !bytes.Equal(got, content) {
		t.Fatal("file from a legacy console differs")
	}

	// A wrong file is removed.
	bad := &pkgServer{content: append([]byte("X"), content[1:]...)}
	dest3 := filepath.Join(t.TempDir(), "setup.msi")
	if err := pkgSession(t, bad).FetchPackage(context.Background(), "job", ref, dest3); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("wrong package: %v", err)
	}
	if _, err := os.Stat(dest3); !os.IsNotExist(err) {
		t.Fatal("wrong package kept")
	}
}
