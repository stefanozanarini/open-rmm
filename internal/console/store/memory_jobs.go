package store

import (
	"context"
	"sort"
	"time"
)

func (m *Memory) PutModule(_ context.Context, mod Module) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := mod.ID + "@" + mod.Version
	if _, ok := m.modules[k]; ok {
		return ErrModuleExists
	}
	if mod.UploadedAt.IsZero() {
		mod.UploadedAt = time.Now()
	}
	m.modules[k] = mod
	return nil
}

func (m *Memory) GetModule(_ context.Context, id, version string) (Module, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mod, ok := m.modules[id+"@"+version]
	if !ok {
		return Module{}, ErrNotFound
	}
	return mod, nil
}

func (m *Memory) ListModules(_ context.Context) ([]Module, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Module
	for _, mod := range m.modules {
		mod.Archive = nil
		out = append(out, mod)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID+out[i].Version < out[j].ID+out[j].Version })
	return out, nil
}

func (m *Memory) CreateJob(_ context.Context, j Job) error {
	m.mu.Lock()
	if _, ok := m.agents[agentKey(j.TenantID, j.AgentID)]; !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if _, ok := m.modules[j.Module+"@"+j.ModuleVersion]; !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now()
	}
	j.State = JobQueued
	m.jobs[agentKey(j.TenantID, j.ID)] = j
	listeners := append([]func(string){}, m.listeners...)
	m.mu.Unlock()
	for _, fn := range listeners {
		fn(WakeKey(j.TenantID, j.AgentID))
	}
	return nil
}

func (m *Memory) GetJob(_ context.Context, tenantID, jobID string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[agentKey(tenantID, jobID)]
	if !ok {
		return Job{}, ErrNotFound
	}
	return j, nil
}

func (m *Memory) ListJobs(_ context.Context, tenantID, agentID string, limit int) ([]Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Job
	for _, j := range m.jobs {
		if j.TenantID == tenantID && (agentID == "" || j.AgentID == agentID) {
			out = append(out, j)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.After(out[b].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) DispatchableJobs(_ context.Context, tenantID, agentID string, now time.Time) ([]Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Job
	for _, j := range m.jobs {
		if j.TenantID == tenantID && j.AgentID == agentID && (j.State == JobQueued || j.State == JobSent) && j.ExpiresAt.After(now) {
			out = append(out, j)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.Before(out[b].CreatedAt) })
	return out, nil
}

func (m *Memory) MarkJobSent(_ context.Context, tenantID, jobID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(tenantID, jobID)
	j, ok := m.jobs[k]
	if !ok {
		return ErrNotFound
	}
	if j.State == JobQueued {
		j.State = JobSent
	}
	j.SentAt = &at
	m.jobs[k] = j
	return nil
}

func (m *Memory) UpdateJob(_ context.Context, tenantID, agentID, jobID string, u JobUpdate, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := agentKey(tenantID, jobID)
	j, ok := m.jobs[k]
	if !ok || j.AgentID != agentID {
		return ErrNotFound
	}
	if j.State.Final() {
		if j.State == u.State {
			return nil // duplicate delivery from the agent outbox
		}
		return ErrJobFinal
	}
	j.State, j.Progress, j.Message, j.Error = u.State, u.Progress, u.Message, u.Error
	if u.State.Final() {
		j.Result = u.Result
		j.FinishedAt = &at
	}
	m.jobs[k] = j
	return nil
}

func (m *Memory) ListenJobs(ctx context.Context, fn func(string)) error {
	m.mu.Lock()
	m.listeners = append(m.listeners, fn)
	m.mu.Unlock()
	<-ctx.Done()
	return nil
}
