//go:build !windows

package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/modules"
)

func script(t *testing.T, body string) Spec {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "main.sh")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Spec{Type: modules.TypeShell, Path: p, ModuleDir: dir, WorkDir: t.TempDir(), Timeout: 10 * time.Second,
		Request: Request{ProtocolVersion: 1, JobID: "j", Action: "run", Params: json.RawMessage(`{"x":1}`)}}
}

func TestResultAndEvents(t *testing.T) {
	spec := script(t, `read -r req
echo "stray output"
echo '{"type":"progress","percent":150,"message":"half"}'
echo '{"type":"log","level":"warn","message":"careful"}'
printf '{"type":"result","data":{"request":%s,"cwd":"%s","env_home":"%s"}}\n' "$req" "$(pwd)" "$HOME"
`)
	var mu sync.Mutex
	var events []Event
	spec.OnEvent = func(e Event) { mu.Lock(); events = append(events, e); mu.Unlock() }
	out, err := Run(context.Background(), spec)
	if err != nil || out.Err != "" {
		t.Fatalf("run: %v %q (stderr %q)", err, out.Err, out.Stderr)
	}
	var res struct {
		Request Request
		Cwd     string
		EnvHome string `json:"env_home"`
	}
	if err := json.Unmarshal(out.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.Request.Action != "run" || string(res.Request.Params) != `{"x":1}` || res.Cwd != spec.WorkDir || res.EnvHome != spec.WorkDir {
		t.Fatalf("result = %+v", res)
	}
	if len(events) != 3 || events[0].Message != "stray output" || events[1].Percent != 100 || events[2].Level != "warn" {
		t.Fatalf("events = %+v", events)
	}
}

func TestEnvironmentIsMinimal(t *testing.T) {
	t.Setenv("OPENRMM_TEST_SECRET", "leak")
	spec := script(t, `read -r req
printf '{"type":"result","data":{"secret":"%s"}}\n' "${OPENRMM_TEST_SECRET:-}"`)
	out, _ := Run(context.Background(), spec)
	if !strings.Contains(string(out.Result), `"secret":""`) {
		t.Fatalf("service environment leaked to module: %s", out.Result)
	}
}

func TestFailures(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"error event":  {`echo '{"type":"error","message":"boom"}'; exit 1`, "boom"},
		"no result":    {`exit 0`, "without a result"},
		"crash":        {`exit 3`, "code 3"},
		"two finals":   {`echo '{"type":"result","data":1}'; echo '{"type":"result","data":2}'`, "more than one"},
		"invalid data": {`echo '{"type":"result"}'`, "not valid JSON"},
	}
	for name, c := range cases {
		out, err := Run(context.Background(), script(t, c.body))
		if err != nil || !strings.Contains(out.Err, c.want) {
			t.Errorf("%s: err %v, outcome %q, want %q", name, err, out.Err, c.want)
		}
	}
}

func TestTimeoutKillsProcessTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	spec := script(t, `sleep 300 &
echo $! > `+pidFile+`
wait`)
	spec.Timeout = 500 * time.Millisecond
	start := time.Now()
	out, err := Run(context.Background(), spec)
	if err != nil || out.Err != ErrTimeout.Error() {
		t.Fatalf("outcome %q, err %v", out.Err, err)
	}
	if time.Since(start) > 8*time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("child process survived the timeout")
	}
}

func TestOversizedLine(t *testing.T) {
	out, _ := Run(context.Background(), script(t, `head -c 2000000 /dev/zero | tr '\0' 'a'; echo`))
	if !strings.Contains(out.Err, "too long") {
		t.Fatalf("outcome %q", out.Err)
	}
}

func TestOutputLimit(t *testing.T) {
	start := time.Now()
	out, _ := Run(context.Background(), script(t, `while :; do echo '{"type":"log","message":"spam spam spam spam spam spam spam spam"}'; done`))
	if !strings.Contains(out.Err, "too large") || time.Since(start) > 8*time.Second {
		t.Fatalf("outcome %q after %s", out.Err, time.Since(start))
	}
}
