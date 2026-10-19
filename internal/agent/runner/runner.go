// Package runner executes one module action as a child process and speaks
// the core↔module protocol (version 1) with it:
//
//   - the core writes one JSON request line on the module's stdin, then
//     closes it;
//   - the module writes JSON lines on stdout, each an Event: "progress",
//     "log", and exactly one final "result" or "error".
//
// Stdout lines that are not protocol events are kept as log lines, so stray
// output (common in PowerShell) never breaks a module.
package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const (
	maxLine       = 1 << 20
	maxStdout     = 16 << 20
	MaxResult     = 3 << 20 // must fit a gRPC message with some headroom
	maxStderr     = 64 << 10
	maxLogMessage = 2000
	killGrace     = 5 * time.Second
)

// Request is the first and only line sent to the module.
type Request struct {
	ProtocolVersion int             `json:"protocol_version"`
	JobID           string          `json:"job_id"`
	Action          string          `json:"action"`
	Params          json.RawMessage `json:"params"`
	TenantID        string          `json:"tenant_id"`
	AgentID         string          `json:"agent_id"`
	WorkDir         string          `json:"work_dir"`
	// StateDir persists between runs of the same module (e.g. a read
	// position); it is private to the module.
	StateDir string `json:"state_dir,omitempty"`
}

// Event is one line written by the module.
type Event struct {
	Type    string          `json:"type"`
	Percent int             `json:"percent,omitempty"`
	Level   string          `json:"level,omitempty"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Spec describes one execution.
type Spec struct {
	Type      string // modules.Type*
	Path      string // absolute path of the entrypoint
	ModuleDir string
	WorkDir   string // created by the caller, removed afterwards
	StateDir  string // created by the caller, kept
	Timeout   time.Duration
	Request   Request
	// OnEvent receives progress and log events while the module runs.
	OnEvent func(Event)
}

// Outcome is the end of an execution.
type Outcome struct {
	Result   json.RawMessage // set on success
	Err      string          // set on failure
	ExitCode int
	Stderr   string
	Duration time.Duration
}

// ErrTimeout is reported in Outcome.Err when the module ran too long.
var ErrTimeout = errors.New("module timed out")

// Run executes spec. It returns an error only if the module could not be
// started; failures of the module itself are reported in Outcome.
func Run(ctx context.Context, spec Spec) (Outcome, error) {
	req, err := json.Marshal(spec.Request)
	if err != nil {
		return Outcome{}, err
	}
	cmd, err := command(spec)
	if err != nil {
		return Outcome{}, err
	}
	cmd.Dir = spec.WorkDir
	cmd.Env = environment(spec)
	cmd.Stdin = bytes.NewReader(append(req, '\n'))
	stderr := &capped{max: maxStderr}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Outcome{}, err
	}
	cmd.WaitDelay = killGrace

	start := time.Now()
	tree, err := startTree(cmd)
	if err != nil {
		return Outcome{}, fmt.Errorf("start module: %w", err)
	}
	defer tree.close()

	var (
		mu         sync.Mutex
		final      *Event
		multiFinal bool
		readErr    string
	)
	parsed := make(chan struct{})
	go func() {
		defer close(parsed)
		limited := &io.LimitedReader{R: stdout, N: maxStdout}
		defer func() {
			if limited.N <= 0 && readErr == "" {
				readErr = "module output too large"
			}
			// A module that broke the protocol is stopped at once instead of
			// blocking on a full pipe until its timeout.
			if readErr != "" {
				tree.kill()
			}
			_, _ = io.Copy(io.Discard, stdout)
		}()
		readErr = readEvents(limited, func(ev Event) {
			switch ev.Type {
			case "result", "error":
				mu.Lock()
				defer mu.Unlock()
				if final == nil {
					e := ev
					final = &e
				} else {
					multiFinal = true
				}
			default:
				if spec.OnEvent != nil {
					spec.OnEvent(ev)
				}
			}
		})
	}()

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	waitErr := make(chan error, 1)
	go func() {
		<-parsed // drain stdout before Wait closes the pipe
		waitErr <- cmd.Wait()
	}()

	out := Outcome{}
	var werr error
	select {
	case werr = <-waitErr:
	case <-timer.C:
		tree.kill()
		<-waitErr
		out.Err = ErrTimeout.Error()
	case <-ctx.Done():
		tree.kill()
		<-waitErr
		out.Err = "agent stopping: module interrupted"
	}
	// Grandchildren may outlive the module: terminate whatever is left.
	tree.kill()
	out.Duration = time.Since(start)
	out.Stderr = stderr.String()
	if cmd.ProcessState != nil {
		out.ExitCode = cmd.ProcessState.ExitCode()
	}
	if out.Err != "" {
		return out, nil
	}
	mu.Lock()
	defer mu.Unlock()
	switch {
	case readErr != "":
		out.Err = readErr
	case multiFinal:
		out.Err = "module sent more than one final event"
	case final == nil && werr != nil:
		out.Err = fmt.Sprintf("module exited with code %d without a result", out.ExitCode)
	case final == nil:
		out.Err = "module exited without a result"
	case final.Type == "error":
		out.Err = truncate(final.Message, maxLogMessage)
		if out.Err == "" {
			out.Err = "module reported an error"
		}
	case len(final.Data) > MaxResult:
		out.Err = "module result too large"
	case !json.Valid(final.Data) || len(final.Data) == 0:
		out.Err = "module result is not valid JSON"
	default:
		out.Result = final.Data
	}
	return out, nil
}

// readEvents parses stdout. It returns a protocol error description, or "".
func readEvents(r io.Reader, emit func(Event)) string {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev Event
		if line[0] != '{' || json.Unmarshal(line, &ev) != nil || ev.Type == "" {
			emit(Event{Type: "log", Level: "info", Message: truncate(string(line), maxLogMessage)})
			continue
		}
		switch ev.Type {
		case "progress":
			ev.Percent = max(0, min(100, ev.Percent))
			ev.Message = truncate(ev.Message, maxLogMessage)
		case "log":
			switch ev.Level {
			case "debug", "info", "warn", "error":
			default:
				ev.Level = "info"
			}
			ev.Message = truncate(ev.Message, maxLogMessage)
		case "result", "error":
		default:
			emit(Event{Type: "log", Level: "warn", Message: "unknown event type " + truncate(ev.Type, 40)})
			continue
		}
		emit(ev)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return "module output line too long"
		}
		return "reading module output: " + err.Error()
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// capped keeps the first max bytes written to it.
type capped struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// environment builds a minimal environment: nothing from the service's own
// environment is passed through except the variables listed per OS.
func environment(spec Spec) []string {
	env := baseEnvironment(spec.WorkDir)
	return append(env,
		"OPENRMM_PROTOCOL_VERSION=1",
		"OPENRMM_MODULE_DIR="+spec.ModuleDir,
		"OPENRMM_WORK_DIR="+spec.WorkDir,
		"OPENRMM_STATE_DIR="+spec.StateDir,
	)
}

func passthrough(names ...string) []string {
	var out []string
	for _, n := range names {
		if v, ok := os.LookupEnv(n); ok {
			out = append(out, n+"="+v)
		}
	}
	return out
}
