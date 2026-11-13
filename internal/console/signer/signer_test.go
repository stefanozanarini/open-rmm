package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/console/assignreq"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/signing"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := signing.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	// No operator verifier: these tests exercise SignAssignmentRun, which
	// never checks an id_token.
	srv, err := New(sg, nil, filepath.Join(t.TempDir(), "used.json"), discardLog())
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func sampleAssignment(t *testing.T, now time.Time) *openrmmv1.AssignmentRequest {
	t.Helper()
	sum := sha256.Sum256([]byte("manifest"))
	return &openrmmv1.AssignmentRequest{
		TenantId: ids.NewUUID(), WorkflowId: ids.NewUUID(), GroupId: ids.NewUUID(), Revision: 1,
		Module: "workflow", ModuleVersion: "1.0.0", ModuleSha256: sum[:], Action: "run",
		ParamsJson: []byte(`{"workflow_id":"x"}`), MaxTtlSeconds: int64((24 * time.Hour).Seconds()),
		ExpiresUnix: now.Add(90 * 24 * time.Hour).Unix(), RequestNonce: []byte("0123456789abcdef"),
	}
}

// signedEnvelope signs payload as domain d with s's key and serializes the
// envelope, as SignAssignment would.
func signedEnvelope(s *signing.Signer, d signing.Domain, payload []byte) []byte {
	raw, _ := proto.Marshal(&openrmmv1.SignedEnvelope{KeyId: s.KeyID(), Payload: payload, Signature: s.Sign(d, payload)})
	return raw
}

func TestSignAssignmentRun(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now()
	srv.now = func() time.Time { return now }
	a := sampleAssignment(t, now)
	payload, _ := proto.Marshal(a)
	env := signedEnvelope(srv.signer, signing.DomainAssignment, payload)
	agents := []string{ids.NewUUID(), ids.NewUUID()}

	resp, err := srv.SignAssignmentRun(context.Background(), &openrmmv1.SignAssignmentRunRequest{
		AssignmentEnvelope: env, AgentIds: agents, TtlSeconds: 3600})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(resp.GetJobs()) != 2 {
		t.Fatalf("jobs = %d", len(resp.GetJobs()))
	}
	for _, sj := range resp.GetJobs() {
		jenv := &openrmmv1.SignedEnvelope{}
		proto.Unmarshal(sj.GetEnvelope(), jenv)
		job := &openrmmv1.Job{}
		proto.Unmarshal(jenv.GetPayload(), job)
		if job.GetModule() != "workflow" || string(job.GetParamsJson()) != string(a.GetParamsJson()) ||
			job.GetTenantId() != a.GetTenantId() {
			t.Fatalf("issued job = %+v", job)
		}
		// Signed with the job domain, not the assignment's.
		if srv.signer.Verify(signing.DomainJob, jenv.GetKeyId(), jenv.GetPayload(), jenv.GetSignature()) != nil {
			t.Fatal("issued job not signed for DomainJob")
		}
	}
}

func TestSignAssignmentRunRejectsTampering(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now()
	srv.now = func() time.Time { return now }
	a := sampleAssignment(t, now)
	payload, _ := proto.Marshal(a)
	good := signedEnvelope(srv.signer, signing.DomainAssignment, payload)
	targets := []string{ids.NewUUID()}

	cases := map[string][]byte{
		"wrong domain (signed as a job, not an assignment)": signedEnvelope(srv.signer, signing.DomainJob, payload),
		"garbage envelope": []byte("not an envelope"),
	}
	// A tampered payload: same envelope bytes, one bit flipped.
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 1
	cases["tampered envelope"] = tampered
	// Signed by a different key entirely.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := signing.NewSigner(otherPriv)
	cases["signed by another key"] = signedEnvelope(other, signing.DomainAssignment, payload)

	for name, env := range cases {
		if _, err := srv.SignAssignmentRun(context.Background(), &openrmmv1.SignAssignmentRunRequest{
			AssignmentEnvelope: env, AgentIds: targets, TtlSeconds: 3600}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSignAssignmentRunRejectsExpired(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now()
	a := sampleAssignment(t, now)
	a.ExpiresUnix = now.Add(-time.Minute).Unix() // already in the past
	payload, _ := proto.Marshal(a)
	env := signedEnvelope(srv.signer, signing.DomainAssignment, payload)
	srv.now = func() time.Time { return now } // the signer sees it as expired at the moment of the call

	if _, err := srv.SignAssignmentRun(context.Background(), &openrmmv1.SignAssignmentRunRequest{
		AssignmentEnvelope: env, AgentIds: []string{ids.NewUUID()}, TtlSeconds: 3600}); err == nil {
		t.Fatal("expired assignment accepted")
	}
}

func TestSignAssignmentRunCapsTargetsAndTTL(t *testing.T) {
	srv := newTestServer(t)
	now := time.Now()
	srv.now = func() time.Time { return now }
	a := sampleAssignment(t, now)
	a.MaxTtlSeconds = 3600
	payload, _ := proto.Marshal(a)
	env := signedEnvelope(srv.signer, signing.DomainAssignment, payload)

	if _, err := srv.SignAssignmentRun(context.Background(), &openrmmv1.SignAssignmentRunRequest{
		AssignmentEnvelope: env, AgentIds: []string{ids.NewUUID()}, TtlSeconds: 7200}); err == nil {
		t.Fatal("ttl beyond the assignment's maximum accepted")
	}
	var many []string
	for i := 0; i < assignreq.MaxAgents+1; i++ {
		many = append(many, ids.NewUUID())
	}
	if _, err := srv.SignAssignmentRun(context.Background(), &openrmmv1.SignAssignmentRunRequest{
		AssignmentEnvelope: env, AgentIds: many, TtlSeconds: 3600}); err == nil {
		t.Fatal("too many targets accepted")
	}
	if _, err := srv.SignAssignmentRun(context.Background(), &openrmmv1.SignAssignmentRunRequest{
		AssignmentEnvelope: env, AgentIds: []string{"not-a-uuid"}, TtlSeconds: 3600}); err == nil {
		t.Fatal("invalid agent id accepted")
	}
}

// discardLog returns a logger writing nowhere, for noise-free test output.
func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }
