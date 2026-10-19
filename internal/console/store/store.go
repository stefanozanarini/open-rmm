// Package store persists console state.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/console/audit"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrTokenInvalid = errors.New("enrollment token invalid, expired, revoked or exhausted")
	ErrNotPending   = errors.New("agent is not pending approval")
	ErrCertMismatch = errors.New("certificate is neither the current nor the previous one")
)

type Tenant struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

type EnrollmentToken struct {
	ID          string
	TenantID    string
	Description string
	MaxUses     int
	Uses        int
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	// AutoApprove makes agents enrolled with this token active immediately;
	// otherwise they wait for an operator's approval.
	AutoApprove bool
}

type AgentStatus string

const (
	AgentPending AgentStatus = "pending"
	AgentActive  AgentStatus = "active"
	AgentRevoked AgentStatus = "revoked"
)

type HostInfo struct {
	Hostname     string
	OS           string
	OSVersion    string
	Arch         string
	AgentVersion string
	MachineID    string
	OSFamily     string // client | server | unknown
}

type Agent struct {
	TenantID        string
	ID              string
	Status          AgentStatus
	Host            HostInfo
	CertFingerprint string
	CertNotAfter    time.Time
	// PrevCertFingerprint is the certificate replaced by the last renewal,
	// accepted until the agent connects with the new one.
	PrevCertFingerprint string
	EnrolledAt          time.Time
	ApprovedAt          *time.Time
	ApprovedBy          string
	// UpdateRing is "pilot" or "broad".
	UpdateRing      string
	Update          AgentUpdate
	EnrolledTokenID string
	LastSeenAt      *time.Time
	LastSeenIP      *netip.Addr
}

// Store is implemented by the PostgreSQL store and by an in-memory store for
// tests.
type Store interface {
	CreateTenant(ctx context.Context, t Tenant) error
	GetTenant(ctx context.Context, id string) (Tenant, error)

	CreateEnrollmentToken(ctx context.Context, t EnrollmentToken, tokenHash []byte) error
	RevokeEnrollmentToken(ctx context.Context, id string) error
	// ConsumeEnrollmentToken atomically uses one slot of a valid token.
	ConsumeEnrollmentToken(ctx context.Context, tokenHash []byte, now time.Time) (EnrollmentToken, error)

	CreateAgent(ctx context.Context, a Agent) error
	GetAgent(ctx context.Context, tenantID, agentID string) (Agent, error)
	ListAgents(ctx context.Context, tenantID string) ([]Agent, error)
	UpdateAgentSeen(ctx context.Context, tenantID, agentID string, host *HostInfo, seen time.Time, ip *netip.Addr) error
	SetAgentStatus(ctx context.Context, tenantID, agentID string, s AgentStatus) error
	// ApproveAgent moves a pending agent to active.
	ApproveAgent(ctx context.Context, tenantID, agentID, by string, at time.Time) error
	// RotateAgentCert records a renewed certificate. usedFingerprint is the
	// certificate the agent authenticated with; it becomes the previous one.
	RotateAgentCert(ctx context.Context, tenantID, agentID, usedFingerprint, newFingerprint string, notAfter time.Time) error
	// ForgetPrevCert drops the previous certificate once the new one is in use.
	ForgetPrevCert(ctx context.Context, tenantID, agentID string) error

	// AppendAudit assigns Seq, PrevHash and Hash and stores the event.
	AppendAudit(ctx context.Context, e audit.Event) (audit.Event, error)
	ListAudit(ctx context.Context, tenantID string) ([]audit.Event, error)

	JobStore
	SessionStore
	ReleaseStore
	PolicyStore
	InventoryStore
}

// HashToken returns the value stored in place of an enrollment token.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte("openrmm/enrollment-token/v1\x00" + token))
	return sum[:]
}

// prepareAudit normalizes an event before hashing. Timestamps are truncated
// to the microsecond precision of PostgreSQL so the hash survives a round trip.
func prepareAudit(e audit.Event, seq int64, prev []byte) (audit.Event, error) {
	if e.Action == "" {
		return e, audit.ErrEmptyAction
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now()
	}
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	// Hash the details exactly as they will read back from jsonb.
	d, err := normalizeDetails(e.Details)
	if err != nil {
		return e, err
	}
	e.Details = d
	e.Seq = seq
	e.PrevHash = prev
	h, err := audit.ComputeHash(e)
	if err != nil {
		return e, err
	}
	e.Hash = h
	return e, nil
}

func normalizeDetails(d map[string]any) (map[string]any, error) {
	if d == nil {
		return map[string]any{}, nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
