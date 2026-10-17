// Package jobreq defines the canonical hash of a job request, shared by the
// console (which puts it in the step-up authentication nonce) and the signer
// (which recomputes it and compares).
package jobreq

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

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
)

const (
	MaxTTL       = 24 * time.Hour
	MaxParams    = 1 << 20
	nonceRandLen = 16
)

// Validate checks a request before hashing or signing it.
func Validate(r *openrmmv1.JobRequest) error {
	if !ids.IsUUID(r.GetTenantId()) || !ids.IsUUID(r.GetAgentId()) {
		return errors.New("tenant and agent must be UUIDs")
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
	if ttl := time.Duration(r.GetTtlSeconds()) * time.Second; ttl < time.Minute || ttl > MaxTTL {
		return fmt.Errorf("ttl must be between 1m and %s", MaxTTL)
	}
	if len(r.GetRequestNonce()) != nonceRandLen {
		return errors.New("request nonce must be 16 bytes")
	}
	return nil
}

// Hash returns the canonical SHA-256 of a request: every field length-prefixed
// in a fixed order, so no two requests share an encoding.
func Hash(r *openrmmv1.JobRequest) []byte {
	var b bytes.Buffer
	b.WriteString("openrmm/job-request/v1\x00")
	field := func(p []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(p)))
		b.Write(l[:])
		b.Write(p)
	}
	field([]byte(r.GetTenantId()))
	field([]byte(r.GetAgentId()))
	field([]byte(r.GetModule()))
	field([]byte(r.GetModuleVersion()))
	field(r.GetModuleSha256())
	field([]byte(r.GetAction()))
	field(r.GetParamsJson())
	var ttl [8]byte
	binary.BigEndian.PutUint64(ttl[:], uint64(r.GetTtlSeconds())) // #nosec G115 -- validated positive
	field(ttl[:])
	field(r.GetRequestNonce())
	sum := sha256.Sum256(b.Bytes())
	return sum[:]
}

// NewRequestNonce returns the random part of a request.
func NewRequestNonce() []byte { return ids.Random(nonceRandLen) }

// AuthNonce is the OIDC nonce for the step-up authentication approving r.
func AuthNonce(r *openrmmv1.JobRequest) string {
	return "job." + base64.RawURLEncoding.EncodeToString(Hash(r))
}

// CheckAuthNonce reports whether nonce approves exactly r.
func CheckAuthNonce(nonce string, r *openrmmv1.JobRequest) bool {
	want := AuthNonce(r)
	return strings.HasPrefix(nonce, "job.") && subtle.ConstantTimeCompare([]byte(nonce), []byte(want)) == 1
}
