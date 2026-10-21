// Package jobs verifies signed jobs received from the console.
package jobs

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/pkgref"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

const (
	// MaxLifetime bounds expires-not_before: a stolen signed job is useless
	// after at most this long, and the replay cache never grows past it.
	MaxLifetime = 24 * time.Hour
	// clockSkew tolerates small clock differences with the console.
	clockSkew = 2 * time.Minute

	replayFile = "replay-cache.json"
	maxEntries = 100_000
)

var ErrReplay = errors.New("job already received")

// ErrInvalid marks an authentic job addressed to this agent that cannot be
// run (validity window, expiry, missing fields): Verify returns the job too,
// so the agent can tell the console why instead of dropping it silently.
var ErrInvalid = errors.New("invalid job")

// Verifier checks job envelopes.
type Verifier struct {
	keys     *signing.Keyring
	tenantID string
	agentID  string

	mu   sync.Mutex
	path string
	seen map[string]int64 // hex(nonce) -> expires unix
}

// NewVerifier loads the replay cache stored in dataDir.
func NewVerifier(keys *signing.Keyring, tenantID, agentID, dataDir string) (*Verifier, error) {
	v := &Verifier{keys: keys, tenantID: tenantID, agentID: agentID,
		path: filepath.Join(dataDir, replayFile), seen: map[string]int64{}}
	raw, err := os.ReadFile(v.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &v.seen); err != nil {
			// A corrupt cache must not reopen the replay window: refuse to
			// start rather than silently resetting it.
			return nil, fmt.Errorf("replay cache corrupt: %w", err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	return v, nil
}

// Verify authenticates env and returns the job it carries. The nonce is
// recorded and persisted before Verify returns, so a job is accepted at most
// once even across restarts. On ErrReplay the (authentic) job is returned
// too, so the caller can report on it.
func (v *Verifier) Verify(env *openrmmv1.SignedEnvelope, now time.Time) (*openrmmv1.Job, error) {
	if v.keys.Len() == 0 {
		return nil, errors.New("no job signing keys configured")
	}
	if err := v.keys.Verify(signing.DomainJob, env.GetKeyId(), env.GetPayload(), env.GetSignature()); err != nil {
		return nil, err
	}
	job := &openrmmv1.Job{}
	if err := proto.Unmarshal(env.GetPayload(), job); err != nil {
		return nil, fmt.Errorf("job payload: %w", err)
	}
	if job.GetTenantId() != v.tenantID || job.GetAgentId() != v.agentID {
		return nil, errors.New("job addressed to another agent")
	}
	if !ids.IsUUID(job.GetJobId()) || job.GetModule() == "" || job.GetAction() == "" {
		return job, fmt.Errorf("%w: %s", ErrInvalid, "job is missing required fields")
	}
	if len(job.GetModuleSha256()) != 32 {
		return job, fmt.Errorf("%w: %s", ErrInvalid, "job must pin the module hash")
	}
	if err := pkgref.Validate(job.GetPackages()); err != nil {
		return job, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if n := len(job.GetNonce()); n < 16 || n > 64 {
		return job, fmt.Errorf("%w: %s", ErrInvalid, "job nonce must be 16-64 bytes")
	}
	nb, exp := time.Unix(job.GetNotBeforeUnix(), 0), time.Unix(job.GetExpiresUnix(), 0)
	if !exp.After(nb) || exp.Sub(nb) > MaxLifetime {
		return job, fmt.Errorf("%w: %s", ErrInvalid, "job validity window invalid")
	}
	if now.Add(clockSkew).Before(nb) {
		return job, fmt.Errorf("%w: %s", ErrInvalid, "job not yet valid")
	}
	if now.Add(-clockSkew).After(exp) {
		return job, fmt.Errorf("%w: %s", ErrInvalid, "job expired")
	}
	if err := v.remember(job.GetNonce(), exp.Add(clockSkew), now); err != nil {
		if errors.Is(err, ErrReplay) {
			return job, err
		}
		return nil, err
	}
	return job, nil
}

func (v *Verifier) remember(nonce []byte, until, now time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	k := hex.EncodeToString(nonce)
	if _, ok := v.seen[k]; ok {
		return ErrReplay
	}
	for n, e := range v.seen {
		if e < now.Unix() {
			delete(v.seen, n)
		}
	}
	if len(v.seen) >= maxEntries {
		return errors.New("replay cache full")
	}
	v.seen[k] = until.Unix()
	raw, err := json.Marshal(v.seen)
	if err != nil {
		return err
	}
	if err := secfile.WriteFile(v.path, raw); err != nil {
		delete(v.seen, k)
		return fmt.Errorf("persist replay cache: %w", err)
	}
	return nil
}
