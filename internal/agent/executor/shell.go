package executor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/agent/pty"
	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
)

const (
	shellDefault = 30 * time.Minute
	shellMax     = 60 * time.Minute
	// shellIdle ends a session without keystrokes.
	shellIdle  = 15 * time.Minute
	shellChunk = 32 << 10
)

// runShell serves an interactive shell session for a signed job: a fixed
// shell on a pseudo-terminal, started with the module's startup script,
// connected to the console over the Shell stream until the operator closes
// it, the session time is over or it is idle.
func (e *Executor) runShell(job *openrmmv1.Job, startup string, send func(*openrmmv1.JobUpdate), log *slog.Logger) *openrmmv1.JobUpdate {
	var p struct {
		Minutes int `json:"minutes"`
	}
	_ = json.Unmarshal(job.GetParamsJson(), &p)
	limit := shellDefault
	if p.Minutes > 0 {
		limit = min(time.Duration(p.Minutes)*time.Minute, shellMax)
	}
	e.mu.Lock()
	sess := e.session
	e.mu.Unlock()
	if sess == nil {
		return fail(job, "not connected to the console")
	}
	workDir := filepath.Join(e.work, job.GetJobId())
	if err := secfile.EnsureDir(workDir); err != nil {
		return fail(job, "work directory: %v", err)
	}
	defer os.RemoveAll(workDir)

	ctx, cancel := context.WithTimeout(e.ctx, limit)
	defer cancel()
	stream, err := sess.OpenShell(ctx)
	if err != nil {
		return fail(job, "shell stream: %v", err)
	}
	var sendMu sync.Mutex
	sendFrame := func(f *openrmmv1.ShellFrame) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(f)
	}
	if err := sendFrame(&openrmmv1.ShellFrame{JobId: job.GetJobId()}); err != nil {
		return fail(job, "shell stream: %v", err)
	}
	argv, env := shellCommand(startup, workDir)
	proc, err := pty.Start(argv, env, workDir, 120, 30)
	if err != nil {
		_ = sendFrame(&openrmmv1.ShellFrame{Close: true, Error: err.Error()})
		return fail(job, "start shell: %v", err)
	}
	defer proc.Close()
	started := time.Now()
	send(&openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_RUNNING, Message: "shell session open"})
	log.Info("interactive shell open", "limit", limit)

	var bytesIn, bytesOut atomic.Int64
	ended := "timeout"
	var endMu sync.Mutex
	end := func(why string) {
		endMu.Lock()
		if ended == "timeout" {
			ended = why
		}
		endMu.Unlock()
		cancel()
	}
	// Shell output to the console.
	go func() {
		buf := make([]byte, shellChunk)
		for {
			n, err := proc.Read(buf)
			if n > 0 {
				bytesOut.Add(int64(n))
				if sendFrame(&openrmmv1.ShellFrame{Data: append([]byte(nil), buf[:n]...)}) != nil {
					end("disconnected")
					return
				}
			}
			if err != nil {
				end("exited")
				return
			}
		}
	}()
	idle := time.AfterFunc(shellIdle, func() { end("idle") })
	defer idle.Stop()
	// Keystrokes and window size from the console.
	go func() {
		for {
			f, err := stream.Recv()
			if err != nil {
				end("disconnected")
				return
			}
			if f.GetClose() {
				end("closed")
				return
			}
			if f.GetCols() > 0 && f.GetRows() > 0 {
				_ = proc.Resize(uint16(min(f.GetCols(), 1000)), uint16(min(f.GetRows(), 1000))) // #nosec G115 -- clamped
			}
			if d := f.GetData(); len(d) > 0 {
				idle.Reset(shellIdle)
				bytesIn.Add(int64(len(d)))
				if _, err := proc.Write(d); err != nil {
					end("exited")
					return
				}
			}
		}
	}()
	<-ctx.Done()
	proc.Close()
	endMu.Lock()
	why := ended
	endMu.Unlock()
	_ = sendFrame(&openrmmv1.ShellFrame{Close: true})
	_ = stream.CloseSend()
	if errors.Is(e.ctx.Err(), context.Canceled) {
		why = "agent stopping"
	}
	log.Info("interactive shell closed", "ended", why, "duration", time.Since(started).Round(time.Second))
	res, _ := json.Marshal(map[string]any{"ended": why, "duration_seconds": int(time.Since(started).Seconds()),
		"bytes_in": bytesIn.Load(), "bytes_out": bytesOut.Load()})
	return &openrmmv1.JobUpdate{JobId: job.GetJobId(), State: openrmmv1.JobUpdate_STATE_SUCCEEDED, ResultJson: res, ProgressPercent: 100}
}
