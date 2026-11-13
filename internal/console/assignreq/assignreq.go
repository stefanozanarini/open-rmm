// Package assignreq defines the canonical hash of a permanent workflow
// assignment, shared by the console (which puts it in the step-up
// authentication nonce when an administrator approves the assignment) and
// the signer (which recomputes it and compares). It mirrors jobreq, with no
// agent targeting: an assignment names a workflow revision and its
// parameters, not yet the computers it will run on.
package assignreq

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/ids"
	"github.com/stefanozanarini/tempra-rmm/internal/modules"
	"github.com/stefanozanarini/tempra-rmm/internal/pkgref"
)

const (
	// MaxAgents bounds the agents one SignAssignmentRun call issues jobs
	// for; jobreq.MaxAgents would also do, but a run is an unattended,
	// recurring call, so it is kept well below the ceiling of a single
	// operator-approved job.
	MaxAgents = 200
	// MinTTL and MaxTTL bound an assignment's max_ttl_seconds (the ceiling
	// it sets for every job a run issues).
	MinTTL = time.Minute
	MaxTTL = 48 * time.Hour
	// MinValidity and MaxValidity bound how long an assignment can be used
	// to sign runs before an administrator must approve it again.
	MinValidity  = 24 * time.Hour
	MaxValidity  = 366 * 24 * time.Hour
	MaxParams    = 1 << 20
	nonceRandLen = 16
)

// Validate checks an assignment before hashing or signing it. now is used
// only to bound expires_unix to a sensible range, not to reject one already
// past (SignAssignmentRun checks that at the time it matters).
func Validate(r *openrmmv1.AssignmentRequest, now time.Time) error {
	if !ids.IsUUID(r.GetTenantId()) {
		return errors.New("tenant must be a UUID")
	}
	if !ids.IsUUID(r.GetWorkflowId()) {
		return errors.New("workflow must be a UUID")
	}
	if !ids.IsUUID(r.GetGroupId()) {
		return errors.New("group must be a UUID")
	}
	if r.GetRevision() < 1 {
		return errors.New("revision must be positive")
	}
	if err := pkgref.Validate(r.GetPackages()); err != nil {
		return err
	}
	if !modules.ValidID(r.GetModule()) || !modules.ValidVersion(r.GetModuleVersion()) {
		return errors.New("invalid module reference")
	}
	if len(r.GetModuleSha256()) != sha256.Size {
		return errors.New("module hash must be SHA-256")
	}
	if a := r.GetAction(); a == "" || len(a) > 41 {
		return errors.New("invalid action")
	}
	if len(r.GetParamsJson()) > MaxParams {
		return errors.New("parameters too large")
	}
	var obj map[string]any
	if err := json.Unmarshal(r.GetParamsJson(), &obj); err != nil {
		return errors.New("parameters must be a JSON object")
	}
	if ttl := time.Duration(r.GetMaxTtlSeconds()) * time.Second; ttl < MinTTL || ttl > MaxTTL {
		return fmt.Errorf("max ttl must be between %s and %s", MinTTL, MaxTTL)
	}
	valid := time.Unix(r.GetExpiresUnix(), 0).Sub(now)
	if valid < MinValidity || valid > MaxValidity {
		return fmt.Errorf("validity must be between %s and %s", MinValidity, MaxValidity)
	}
	if len(r.GetRequestNonce()) != nonceRandLen {
		return errors.New("request nonce must be 16 bytes")
	}
	return nil
}

// Hash returns the canonical SHA-256 of an assignment request: every field
// length-prefixed in a fixed order, so no two requests share an encoding.
func Hash(r *openrmmv1.AssignmentRequest) []byte {
	var b bytes.Buffer
	b.WriteString("openrmm/assignment-request/v1\x00")
	field := func(p []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(p)))
		b.Write(l[:])
		b.Write(p)
	}
	field([]byte(r.GetTenantId()))
	field([]byte(r.GetWorkflowId()))
	var rev [4]byte
	binary.BigEndian.PutUint32(rev[:], uint32(r.GetRevision())) // #nosec G115 -- validated positive
	field(rev[:])
	field([]byte(r.GetModule()))
	field([]byte(r.GetModuleVersion()))
	field(r.GetModuleSha256())
	field([]byte(r.GetAction()))
	field(r.GetParamsJson())
	count := func(n int) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], uint64(n)) // #nosec G115 -- small, validated
		field(c[:])
	}
	count(len(r.GetPackages()))
	for _, p := range r.GetPackages() {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(p.GetSize())) // #nosec G115 -- validated positive
		field(p.GetSha256())
		field([]byte(p.GetFileName()))
		field(size[:])
	}
	var ttl, exp [8]byte
	binary.BigEndian.PutUint64(ttl[:], uint64(r.GetMaxTtlSeconds())) // #nosec G115 -- validated positive
	field(ttl[:])
	binary.BigEndian.PutUint64(exp[:], uint64(r.GetExpiresUnix())) // #nosec G115 -- validated positive
	field(exp[:])
	field(r.GetRequestNonce())
	field([]byte(r.GetGroupId()))
	sum := sha256.Sum256(b.Bytes())
	return sum[:]
}

// NewRequestNonce returns the random part of a request.
func NewRequestNonce() []byte { return ids.Random(nonceRandLen) }

// AuthNonce is the OIDC nonce for the step-up authentication approving r.
func AuthNonce(r *openrmmv1.AssignmentRequest) string {
	return "assignment." + base64.RawURLEncoding.EncodeToString(Hash(r))
}

// CheckAuthNonce reports whether nonce approves exactly r.
func CheckAuthNonce(nonce string, r *openrmmv1.AssignmentRequest) bool {
	want := AuthNonce(r)
	return strings.HasPrefix(nonce, "assignment.") && subtle.ConstantTimeCompare([]byte(nonce), []byte(want)) == 1
}

// ValidateTargets requires 1 to max distinct agent UUIDs.
func ValidateTargets(agentIDs []string, max int) error {
	if n := len(agentIDs); n == 0 || n > max {
		return fmt.Errorf("between 1 and %d agents", max)
	}
	seen := map[string]bool{}
	for _, a := range agentIDs {
		if !ids.IsUUID(a) || seen[a] {
			return errors.New("agents must be distinct UUIDs")
		}
		seen[a] = true
	}
	return nil
}
