package jobs

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

type fixture struct {
	signer   *signing.Signer
	keys     *signing.Keyring
	tenantID string
	agentID  string
	dir      string
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := signing.NewSigner(priv)
	k := signing.NewKeyring()
	if _, err := k.Add(pub, signing.DomainJob); err != nil {
		t.Fatal(err)
	}
	return &fixture{signer: s, keys: k, tenantID: ids.NewUUID(), agentID: ids.NewUUID(), dir: t.TempDir(), now: time.Now()}
}

func (f *fixture) job() *openrmmv1.Job {
	return &openrmmv1.Job{
		JobId: ids.NewUUID(), TenantId: f.tenantID, AgentId: f.agentID,
		Module: "inventory", ModuleVersion: "1.0.0", ModuleSha256: make([]byte, 32), Action: "hardware",
		NotBeforeUnix: f.now.Add(-time.Minute).Unix(), ExpiresUnix: f.now.Add(time.Hour).Unix(),
		Nonce: ids.Random(16),
	}
}

func (f *fixture) seal(j *openrmmv1.Job) *openrmmv1.SignedEnvelope {
	payload, _ := proto.Marshal(j)
	return &openrmmv1.SignedEnvelope{KeyId: f.signer.KeyID(), Payload: payload, Signature: f.signer.Sign(signing.DomainJob, payload)}
}

func (f *fixture) verifier(t *testing.T) *Verifier {
	v, err := NewVerifier(f.keys, f.tenantID, f.agentID, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyAcceptsValidJobOnce(t *testing.T) {
	f := newFixture(t)
	env := f.seal(f.job())
	if _, err := f.verifier(t).Verify(env, f.now); err != nil {
		t.Fatal(err)
	}
	// Replays are refused, also by a fresh verifier (agent restart).
	if _, err := f.verifier(t).Verify(env, f.now); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after restart: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(*openrmmv1.Job){
		"other agent":  func(j *openrmmv1.Job) { j.AgentId = ids.NewUUID() },
		"other tenant": func(j *openrmmv1.Job) { j.TenantId = ids.NewUUID() },
		"expired": func(j *openrmmv1.Job) {
			j.ExpiresUnix = f.now.Add(-time.Hour).Unix()
			j.NotBeforeUnix = f.now.Add(-2 * time.Hour).Unix()
		},
		"not yet valid": func(j *openrmmv1.Job) {
			j.NotBeforeUnix = f.now.Add(time.Hour).Unix()
			j.ExpiresUnix = f.now.Add(2 * time.Hour).Unix()
		},
		"lifetime too long": func(j *openrmmv1.Job) { j.ExpiresUnix = f.now.Add(48 * time.Hour).Unix() },
		"short nonce":       func(j *openrmmv1.Job) { j.Nonce = []byte("x") },
		"no module hash":    func(j *openrmmv1.Job) { j.ModuleSha256 = nil },
		"no action":         func(j *openrmmv1.Job) { j.Action = "" },
	}
	v := f.verifier(t)
	for name, mutate := range cases {
		j := f.job()
		mutate(j)
		if _, err := v.Verify(f.seal(j), f.now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	env := f.seal(f.job())
	env.Payload[len(env.Payload)-1] ^= 1
	if _, err := v.Verify(env, f.now); !errors.Is(err, signing.ErrBadSignature) {
		t.Errorf("tampered payload: %v", err)
	}
	// A key from another console is not trusted.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	os, _ := signing.NewSigner(other)
	payload, _ := proto.Marshal(f.job())
	if _, err := v.Verify(&openrmmv1.SignedEnvelope{KeyId: os.KeyID(), Payload: payload,
		Signature: os.Sign(signing.DomainJob, payload)}, f.now); !errors.Is(err, signing.ErrUnknownKey) {
		t.Errorf("untrusted key: %v", err)
	}
}

// An authentic job that cannot run is returned with ErrInvalid, so the agent
// reports it; a forged one is not.
func TestVerifyReturnsInvalidAuthenticJob(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	j := f.job()
	j.ExpiresUnix = j.GetNotBeforeUnix() + int64(MaxLifetime/time.Second) + 60
	got, err := v.Verify(f.seal(j), time.Now())
	if !errors.Is(err, ErrInvalid) || got.GetJobId() != j.GetJobId() {
		t.Fatalf("got %v, %v", got, err)
	}
	env := f.seal(f.job())
	env.Signature[0] ^= 1
	if got, err := v.Verify(env, time.Now()); err == nil || got != nil {
		t.Fatalf("forged job returned: %v, %v", got, err)
	}
}
