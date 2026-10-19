// Package executor runs verified jobs, and scheduled policy rules, through
// modules.
//
// Final updates (job updates and policy results) are written to an on-disk
// outbox before being sent and are deleted only when the console
// acknowledges them, so a result survives disconnections and restarts.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/config"
	"github.com/stefanozanarini/open-rmm/internal/agent/modcache"
	"github.com/stefanozanarini/open-rmm/internal/agent/runner"
	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
	"github.com/stefanozanarini/open-rmm/internal/ids"
	"github.com/stefanozanarini/open-rmm/internal/modules"
)

// Session is the live connection to the console, if any.
type Session interface {
	Send(*openrmmv1.AgentMessage)
	modcache.Fetcher
}

// PolicyRun identifies a scheduled run of a policy rule.
type PolicyRun struct {
	PolicyID      string
	PolicyVersion int64
	RuleID        string
}

func jobMsg(u *openrmmv1.JobUpdate) *openrmmv1.AgentMessage {
	return &openrmmv1.AgentMessage{Msg: &openrmmv1.AgentMessage_JobUpdate{JobUpdate: u}}
}

// Executor runs jobs, at most cfg.MaxConcurrentJobs at a time.
type Executor struct {
	cfg      *config.Config
	cache    *modcache.Cache
	tenantID string
	agentID  string
	log      *slog.Logger
	sem      chan struct{}
	outbox   string
	work     string
	platform string

	ctx context.Context

	mu      sync.Mutex
	session Session
	running map[string]bool
	wg      sync.WaitGroup
}

// New prepares an executor. ctx bounds every job: cancelling it interrupts
// running modules.
func New(ctx context.Context, cfg *config.Config, tenantID, agentID string, log *slog.Logger) (*Executor, error) {
	cache, err := modcache.New(cfg.DataDir, cfg.ModuleKeyring())
	if err != nil {
		return nil, err
	}
	e := &Executor{
		cfg: cfg, cache: cache, tenantID: tenantID, agentID: agentID, log: log,
		sem:      make(chan struct{}, cfg.MaxConcurrentJobs),
		outbox:   filepath.Join(cfg.DataDir, "outbox"),
		work:     filepath.Join(cfg.DataDir, "work"),
		platform: runtime.GOOS + "/" + runtime.GOARCH,
		ctx:      ctx,
		running:  map[string]bool{},
	}
	for _, d := range []string{e.outbox, e.work} {
		if err := secfile.EnsureDir(d); err != nil {
			return nil, err
		}
	}
	// Work directories left by a crash are of no use any more.
	if entries, err := os.ReadDir(e.work); err == nil {
		for _, en := range entries {
			_ = os.RemoveAll(filepath.Join(e.work, en.Name()))
		}
	}
	return e, nil
}

// Attach makes s the live session and resends pending final updates.
func (e *Executor) Attach(s Session) {
	e.mu.Lock()
	e.session = s
	e.mu.Unlock()
	for _, m := range e.pending() {
		s.Send(m)
	}
}

// Detach forgets the session; progress is dropped until the next Attach.
func (e *Executor) Detach(s Session) {
	e.mu.Lock()
	if e.session == s {
		e.session = nil
	}
	e.mu.Unlock()
}

// Wait blocks until all running jobs have finished.
func (e *Executor) Wait() { e.wg.Wait() }

func (e *Executor) send(u *openrmmv1.JobUpdate) { e.sendMsg(jobMsg(u)) }

func (e *Executor) sendMsg(m *openrmmv1.AgentMessage) {
	e.mu.Lock()
	s := e.session
	e.mu.Unlock()
	if s != nil {
		s.Send(m)
	}
}

func (e *Executor) fetcher() (modcache.Fetcher, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == nil {
		return nil, errors.New("not connected to the console")
	}
	return e.session, nil
}

// lazyFetcher resolves the session only when a download is needed.
type lazyFetcher struct{ e *Executor }

func (l lazyFetcher) FetchModule(ctx context.Context, id, version string) (*modcache.Fetched, error) {
	f, err := l.e.fetcher()
	if err != nil {
		return nil, err
	}
	return f.FetchModule(ctx, id, version)
}

// Acked removes a final update (job id or policy run id) from the outbox.
func (e *Executor) Acked(id string) {
	if ids.IsUUID(id) {
		_ = os.Remove(filepath.Join(e.outbox, id+".msg"))
	}
}

// Replayed handles a job the agent has already seen (the console delivers
// unanswered jobs again after a reconnection).
func (e *Executor) Replayed(jobID string) {
	if !ids.IsUUID(jobID) {
		return
	}
	e.mu.Lock()
	running := e.running[jobID]
	e.mu.Unlock()
	if running {
		e.send(&openrmmv1.JobUpdate{JobId: jobID, State: openrmmv1.JobUpdate_STATE_RUNNING})
		return
	}
	if m, err := e.readOutbox(jobID); err == nil {
		e.sendMsg(m)
		return
	}
	// Seen but neither running nor finished: the agent stopped mid-job.
	e.finish(&openrmmv1.JobUpdate{JobId: jobID, State: openrmmv1.JobUpdate_STATE_FAILED,
		Error: "interrupted: the agent restarted while the job was running"})
}

// Start runs job asynchronously.
func (e *Executor) Start(job *openrmmv1.Job) {
	if !ids.IsUUID(job.GetJobId()) {
		e.log.Warn("job with invalid id ignored")
		return
	}
	e.mu.Lock()
	if e.running[job.GetJobId()] {
		e.mu.Unlock()
		return
	}
	e.running[job.GetJobId()] = true
	e.mu.Unlock()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() {
			e.mu.Lock()
			delete(e.running, job.GetJobId())
			e.mu.Unlock()
		}()
		e.finish(e.run(job, false))
	}()
}

// StartPolicy runs one scheduled policy rule asynchronously. Policy runs are
// quiet (only the final result is reported) and may never use modules that
// run ad-hoc code. done is called with the final result.
func (e *Executor) StartPolicy(job *openrmmv1.Job, pr PolicyRun, done func(*openrmmv1.PolicyResult)) {
	if !ids.IsUUID(job.GetJobId()) {
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		started := time.Now()
		u := e.run(job, true)
		res := &openrmmv1.PolicyResult{
			RunId: job.GetJobId(), PolicyId: pr.PolicyID, PolicyVersion: pr.PolicyVersion, RuleId: pr.RuleID,
			State: u.GetState(), ResultJson: u.GetResultJson(), Error: u.GetError(),
			StartedUnixMs: started.UnixMilli(), FinishedUnixMs: time.Now().UnixMilli(),
		}
		e.finishMsg(res.GetRunId(), &openrmmv1.AgentMessage{Msg: &openrmmv1.AgentMessage_PolicyResult{PolicyResult: res}})
		if done != nil {
			done(res)
		}
	}()
}

func reject(job *openrmmv1.Job, format string, args ...any) *openrmmv1.JobUpdate {
	return &openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_REJECTED, Error: fmt.Sprintf(format, args...)}
}

func fail(job *openrmmv1.Job, format string, args ...any) *openrmmv1.JobUpdate {
	return &openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_FAILED, Error: fmt.Sprintf(format, args...)}
}

// run executes job. quiet suppresses intermediate updates and marks a
// policy run, for which ad-hoc script modules are refused.
func (e *Executor) run(job *openrmmv1.Job, quiet bool) *openrmmv1.JobUpdate {
	send := e.send
	if quiet {
		send = func(*openrmmv1.JobUpdate) {}
	}
	log := e.log.With("job", job.GetJobId(), "module", job.GetModule(), "action", job.GetAction())
	if len(job.GetParamsJson()) > 0 && !json.Valid(job.GetParamsJson()) {
		return reject(job, "job parameters are not valid JSON")
	}
	// The console is needed only to download a module that is not cached:
	// cached modules also run offline (policies).
	inst, err := e.cache.Get(e.ctx, lazyFetcher{e}, job.GetModule(), job.GetModuleVersion(), job.GetModuleSha256())
	if err != nil {
		log.Warn("module unavailable", "err", err)
		return reject(job, "module unavailable: %v", err)
	}
	m := inst.Manifest
	ep, ok := m.Entrypoints[e.platform]
	if !ok {
		return reject(job, "module %s does not support %s", m.ID, e.platform)
	}
	action, ok := m.Actions[job.GetAction()]
	if !ok {
		return reject(job, "module %s has no action %q", m.ID, job.GetAction())
	}
	if action.Context == modules.ContextUser {
		return reject(job, "user-context execution is not available yet")
	}
	if quiet && m.HasCapability(modules.CapAdHocScript) {
		return reject(job, "modules that run ad-hoc code cannot be scheduled by policies")
	}
	// Local policy: decided on the endpoint (MSI/GPO), never by the console.
	if m.HasCapability(modules.CapAdHocScript) && !e.cfg.AdHocScriptsAllowed() {
		log.Warn("ad-hoc script refused by local policy")
		return reject(job, "ad-hoc scripts are disabled by local policy on this endpoint")
	}
	send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_ACCEPTED})

	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-e.ctx.Done():
		return fail(job, "agent stopping")
	}
	workDir := filepath.Join(e.work, job.GetJobId())
	if err := secfile.EnsureDir(workDir); err != nil {
		return fail(job, "work directory: %v", err)
	}
	defer os.RemoveAll(workDir)
	// Re-hash right before running: the cache could have changed since Get.
	if err := modules.VerifyFiles(m, inst.FilesDir); err != nil {
		return reject(job, "module integrity check failed: %v", err)
	}
	send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_RUNNING})
	log.Info("running module")

	params := json.RawMessage(job.GetParamsJson())
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	out, err := runner.Run(e.ctx, runner.Spec{
		Type:      ep.Type,
		Path:      filepath.Join(inst.FilesDir, filepath.FromSlash(ep.Path)),
		ModuleDir: inst.FilesDir,
		WorkDir:   workDir,
		Timeout:   action.Timeout(),
		Request: runner.Request{
			ProtocolVersion: modules.ProtocolVersion, JobID: job.GetJobId(), Action: job.GetAction(),
			Params: params, TenantID: e.tenantID, AgentID: e.agentID, WorkDir: workDir,
		},
		OnEvent: func(ev runner.Event) {
			switch ev.Type {
			case "progress":
				send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_RUNNING,
					ProgressPercent: int32(ev.Percent), Message: ev.Message}) // #nosec G115 -- clamped to 0-100
			case "log":
				log.Info("module log", "level", ev.Level, "message", ev.Message)
			}
		},
	})
	if err != nil {
		return fail(job, "%v", err)
	}
	log.Info("module finished", "duration", out.Duration.Round(1e6), "exit_code", out.ExitCode, "error", out.Err)
	if out.Err != "" {
		msg := out.Err
		if out.Stderr != "" {
			msg += "\nstderr: " + truncate(out.Stderr, 4000)
		}
		return fail(job, "%s", msg)
	}
	return &openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_SUCCEEDED,
		ResultJson: out.Result, ProgressPercent: 100}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// finish stores a final job update in the outbox and sends it.
func (e *Executor) finish(u *openrmmv1.JobUpdate) { e.finishMsg(u.GetJobId(), jobMsg(u)) }

func (e *Executor) finishMsg(id string, m *openrmmv1.AgentMessage) {
	raw, err := proto.Marshal(m)
	if err == nil {
		err = secfile.WriteFile(filepath.Join(e.outbox, id+".msg"), raw)
	}
	if err != nil {
		e.log.Error("outbox write failed", "id", id, "err", err)
	}
	e.sendMsg(m)
}

func (e *Executor) readOutbox(id string) (*openrmmv1.AgentMessage, error) {
	raw, err := os.ReadFile(filepath.Join(e.outbox, id+".msg")) // #nosec G304 -- id validated as UUID
	if err != nil {
		return nil, err
	}
	m := &openrmmv1.AgentMessage{}
	return m, proto.Unmarshal(raw, m)
}

func (e *Executor) pending() []*openrmmv1.AgentMessage {
	entries, err := os.ReadDir(e.outbox)
	if err != nil {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out []*openrmmv1.AgentMessage
	for _, en := range entries {
		id, ok := strings.CutSuffix(en.Name(), ".msg")
		if !ok || !ids.IsUUID(id) {
			continue
		}
		if m, err := e.readOutbox(id); err == nil {
			out = append(out, m)
		}
	}
	return out
}
