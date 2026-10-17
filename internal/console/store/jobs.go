package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrModuleExists = errors.New("module version already published")
	ErrJobFinal     = errors.New("job already in a final state")
)

// Module is a published, signed module version.
type Module struct {
	ID             string
	Version        string
	Description    string
	KeyID          string
	Manifest       []byte
	Signature      []byte
	ManifestSHA256 []byte
	Archive        []byte // empty in listings
	UploadedAt     time.Time
	UploadedBy     string
}

type JobState string

const (
	JobQueued    JobState = "queued"
	JobSent      JobState = "sent"
	JobAccepted  JobState = "accepted"
	JobRunning   JobState = "running"
	JobSucceeded JobState = "succeeded"
	JobFailed    JobState = "failed"
	JobRejected  JobState = "rejected"
	JobExpired   JobState = "expired"
)

// Final reports whether no further update is accepted.
func (s JobState) Final() bool {
	switch s {
	case JobSucceeded, JobFailed, JobRejected, JobExpired:
		return true
	}
	return false
}

type Job struct {
	TenantID      string
	ID            string
	AgentID       string
	Module        string
	ModuleVersion string
	Action        string
	Params        []byte // JSON
	Envelope      []byte // serialized SignedEnvelope
	State         JobState
	Progress      int
	Message       string
	Result        []byte // JSON, final success only
	Error         string
	CreatedBy     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	SentAt        *time.Time
	FinishedAt    *time.Time
}

// JobUpdate is a state change reported by an agent.
type JobUpdate struct {
	State    JobState
	Progress int
	Message  string
	Result   []byte
	Error    string
}

// JobStore is the part of Store dealing with modules and jobs.
type JobStore interface {
	PutModule(ctx context.Context, m Module) error
	GetModule(ctx context.Context, id, version string) (Module, error)
	ListModules(ctx context.Context) ([]Module, error)

	// CreateJob queues a job and wakes up the gateway session of its agent.
	CreateJob(ctx context.Context, j Job) error
	GetJob(ctx context.Context, tenantID, jobID string) (Job, error)
	ListJobs(ctx context.Context, tenantID, agentID string, limit int) ([]Job, error)
	// DispatchableJobs returns queued or sent (but unanswered) jobs of an
	// agent that have not expired, oldest first.
	DispatchableJobs(ctx context.Context, tenantID, agentID string, now time.Time) ([]Job, error)
	MarkJobSent(ctx context.Context, tenantID, jobID string, at time.Time) error
	// UpdateJob applies an agent update to one of its own jobs. Updates to
	// jobs in a final state return ErrJobFinal.
	UpdateJob(ctx context.Context, tenantID, agentID, jobID string, u JobUpdate, at time.Time) error

	// ListenJobs calls fn with "tenant/agent" whenever a job is queued for,
	// or an approval changes, that agent. It blocks until ctx ends.
	ListenJobs(ctx context.Context, fn func(key string)) error
}

// WakeKey identifies an agent in job notifications.
func WakeKey(tenantID, agentID string) string { return tenantID + "/" + agentID }
