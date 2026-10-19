package gateway

import (
	"encoding/hex"
	"errors"
	"io"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
)

const packageChunkSize = 1 << 20

// GetPackage streams a package to an approved agent, only for one of its
// unfinished jobs that references it.
func (s *Server) GetPackage(req *openrmmv1.GetPackageRequest, stream openrmmv1.AgentService_GetPackageServer) error {
	c, ok := callerFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if c.agent.Status != store.AgentActive {
		return status.Error(codes.PermissionDenied, "agent not approved")
	}
	sha := hex.EncodeToString(req.GetSha256())
	if !ids.IsUUID(req.GetJobId()) || len(req.GetSha256()) != 32 {
		return status.Error(codes.InvalidArgument, "invalid request")
	}
	j, err := s.store.GetJob(stream.Context(), c.agent.TenantID, req.GetJobId())
	if err != nil || j.AgentID != c.agent.ID || j.State.Final() || !slices.Contains(j.Packages, sha) {
		s.log.Warn("package refused", "agent", c.agent.ID, "job", req.GetJobId(), "package", sha)
		return status.Error(codes.PermissionDenied, "package not referenced by a pending job of this agent")
	}
	if s.packages.Path == "" {
		return status.Error(codes.Unavailable, "package store not configured")
	}
	f, err := s.packages.Open(sha)
	if err != nil {
		s.log.Error("open package", "package", sha, "err", err)
		return status.Error(codes.NotFound, "package file not found")
	}
	defer f.Close()
	buf := make([]byte, packageChunkSize)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if serr := stream.Send(&openrmmv1.PackageChunk{Data: buf[:n]}); serr != nil {
				return serr
			}
		}
		if errors.Is(err, io.EOF) {
			s.log.Info("package sent", "agent", c.agent.ID, "job", j.ID, "package", sha)
			return nil
		}
		if err != nil {
			return status.Error(codes.Internal, "read package")
		}
	}
}
