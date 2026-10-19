package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/identity"
	"github.com/stefanozanarini/open-rmm/internal/console/store"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/signing"
	"github.com/stefanozanarini/open-rmm/internal/tlsconf"
)

// queueWithPackages signs and queues a job carrying package references.
func (e *env) queueWithPackages(t *testing.T, agentID string, v *modules.Verified, action string, refs []*openrmmv1.PackageRef) string {
	t.Helper()
	now := time.Now()
	job := &openrmmv1.Job{JobId: ids.NewUUID(), TenantId: e.tenant, AgentId: agentID, Module: v.Manifest.ID,
		ModuleVersion: v.Manifest.Version, ModuleSha256: v.ManifestHash, Action: action, ParamsJson: []byte("{}"),
		NotBeforeUnix: now.Add(-time.Minute).Unix(), ExpiresUnix: now.Add(time.Hour).Unix(), Nonce: ids.Random(16), Packages: refs}
	payload, _ := proto.Marshal(job)
	env, _ := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: e.jobSigner.KeyID(), Payload: payload,
		Signature: e.jobSigner.Sign(signing.DomainJob, payload)})
	var shas []string
	for _, r := range refs {
		shas = append(shas, hex.EncodeToString(r.GetSha256()))
	}
	if err := e.store.CreateJob(context.Background(), store.Job{TenantID: e.tenant, ID: job.GetJobId(), AgentID: agentID,
		Module: job.GetModule(), ModuleVersion: job.GetModuleVersion(), Action: action, Params: []byte("{}"),
		Envelope: env, CreatedBy: "test", ExpiresAt: now.Add(time.Hour), Packages: shas}); err != nil {
		t.Fatal(err)
	}
	return job.GetJobId()
}

// The module prints the size and SHA-256 of the package it received.
const packageProbe = `. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"; rmm_read_request
f=$(printf '%s' "$OPENRMM_REQUEST" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
rmm_result "{\"sha\":\"$(sha256sum "$f" | cut -d' ' -f1)\",\"name\":\"$(basename "$f")\"}"`

func TestPackageDeliveredToAgent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the sh entrypoint")
	}
	e := start(t)
	content := []byte(strings.Repeat("installer bytes ", 200000)) // ~3 MB: several chunks
	sha, size, err := e.packages.Save(strings.NewReader(string(content)), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	shaBytes, _ := hex.DecodeString(sha)
	v := e.publish(t, shModule(t, fmt.Sprintf(`{"id":"pkgprobe","version":"1.0.0","protocol_version":1,"entrypoints":{%q:{"type":"sh","path":"main.sh"}},"actions":{"install":{}}}`, platform()), packageProbe))
	cfg, agentID := startAgent(t, e, true)
	ref := &openrmmv1.PackageRef{Sha256: shaBytes, FileName: "Setup 1.0.msi", Size: size}
	j := e.waitFinal(t, e.queueWithPackages(t, agentID, v, "install", []*openrmmv1.PackageRef{ref}))
	if j.State != store.JobSucceeded || !strings.Contains(string(j.Result), sha) || !strings.Contains(string(j.Result), "Setup 1.0.msi") {
		t.Fatalf("job: %s %s %s", j.State, j.Error, j.Result)
	}

	// A file changed on the console is refused by the agent.
	path := filepath.Join(e.packages.Path, sha)
	os.Chmod(path, 0o600)
	os.WriteFile(path, append([]byte("X"), content[1:]...), 0o600)
	j = e.waitFinal(t, e.queueWithPackages(t, agentID, v, "install", []*openrmmv1.PackageRef{ref}))
	if j.State != store.JobFailed || !strings.Contains(j.Error, "SHA-256 mismatch") {
		t.Fatalf("tampered package: %s %q", j.State, j.Error)
	}

	// The gateway serves a package only for a pending job of the agent that references it.
	id, err := identity.Load(cfg.DataDir, cfg.RootCA())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(cfg.Server, grpc.WithTransportCredentials(credentials.NewTLS(
		tlsconf.Client(cfg.ServerName(), cfg.RootCA(), id.Cert, id.Chain, id.Key))))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	get := func(jobID string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := openrmmv1.NewAgentServiceClient(conn).GetPackage(ctx, &openrmmv1.GetPackageRequest{JobId: jobID, Sha256: shaBytes})
		if err != nil {
			return err
		}
		_, err = stream.Recv()
		return err
	}
	if err := get(j.ID); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("package of a finished job: %v", err)
	}
	if err := get(ids.NewUUID()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("package of an unknown job: %v", err)
	}
}
