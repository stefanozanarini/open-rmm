package executor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	openrmmv1 "github.com/stefanozanarini/tempra-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/tempra-rmm/internal/agent/config"
	"github.com/stefanozanarini/tempra-rmm/internal/filesession"
)

const (
	filesDefault = 60 * time.Minute
	filesMax     = 240 * time.Minute
	filesIdle    = 15 * time.Minute
	// filesMaxBytes caps the job's max_bytes.
	filesMaxBytes = 16 << 30
)

// runFiles serves an interactive file session for a signed job over the
// session stream (internal/filesession), until the operator closes it, the
// session time is over or it is idle. The agent's own folders (keys,
// configuration, state, programs) are out of reach.
func (e *Executor) runFiles(job *openrmmv1.Job, send func(*openrmmv1.JobUpdate), log *slog.Logger) *openrmmv1.JobUpdate {
	var p struct {
		Minutes  int   `json:"minutes"`
		MaxBytes int64 `json:"max_bytes"`
	}
	_ = json.Unmarshal(job.GetParamsJson(), &p)
	limit := filesDefault
	if p.Minutes > 0 {
		limit = min(time.Duration(p.Minutes)*time.Minute, filesMax)
	}
	maxBytes := int64(filesMaxBytes)
	if p.MaxBytes > 0 {
		maxBytes = min(p.MaxBytes, maxBytes)
	}
	e.mu.Lock()
	sess := e.session
	e.mu.Unlock()
	if sess == nil {
		return fail(job, "not connected to the console")
	}
	ctx, cancel := context.WithTimeout(e.ctx, limit)
	defer cancel()
	stream, err := sess.OpenShell(ctx)
	if err != nil {
		return fail(job, "session stream: %v", err)
	}
	if err := stream.Send(&openrmmv1.ShellFrame{JobId: job.GetJobId()}); err != nil {
		return fail(job, "session stream: %v", err)
	}
	started := time.Now()
	send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_RUNNING, Message: "file session open"})
	log.Info("file session open", "limit", limit, "max_bytes", maxBytes)

	recv := func() ([]byte, error) {
		for {
			f, err := stream.Recv()
			if err != nil {
				return nil, err
			}
			if f.GetClose() {
				return nil, errors.New("closed by the console")
			}
			if len(f.GetData()) > 0 {
				return f.GetData(), nil
			}
		}
	}
	out := func(b []byte) error { return stream.Send(&openrmmv1.ShellFrame{Data: b}) }
	st, why := filesession.Serve(ctx, recv, out, filesession.Options{
		MaxBytes: maxBytes,
		Deny: []string{e.cfg.DataDir, e.cfg.InstallDir, filepath.Dir(config.DefaultConfigPath()), config.DefaultDataDir(),
			config.DefaultInstallDir()},
		Idle: filesIdle,
		Log: func(op, path string, size int64) {
			log.Info("file session", "op", op, "path", path, "size", size)
		},
	})
	_ = stream.Send(&openrmmv1.ShellFrame{Close: true})
	_ = stream.CloseSend()
	if errors.Is(e.ctx.Err(), context.Canceled) {
		why = "agent stopping"
	}
	log.Info("file session closed", "ended", why, "duration", time.Since(started).Round(time.Second))
	res, _ := json.Marshal(map[string]any{"ended": why, "duration_seconds": int(time.Since(started).Seconds()),
		"downloads": st.Downloads, "uploads": st.Uploads, "bytes_out": st.BytesOut, "bytes_in": st.BytesIn})
	return &openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_SUCCEEDED, ResultJson: res, ProgressPercent: 100}
}
