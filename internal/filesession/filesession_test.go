package filesession

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pair joins a client and a server over channels, like the stream does.
func pair(t *testing.T, o Options) (*Client, chan Stats) {
	t.Helper()
	toAgent, toConsole := make(chan []byte, 64), make(chan []byte, 64)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan Stats, 1)
	go func() {
		st, _ := Serve(ctx, func() ([]byte, error) {
			select {
			case b := <-toAgent:
				return b, nil
			case <-ctx.Done():
				return nil, io.EOF
			}
		}, func(b []byte) error {
			select {
			case toConsole <- append([]byte(nil), b...):
				return nil
			case <-ctx.Done():
				return io.EOF
			}
		}, o)
		done <- st
	}()
	c := NewClient(func() ([]byte, error) {
		select {
		case b := <-toConsole:
			return b, nil
		case <-ctx.Done():
			return nil, io.EOF
		}
	}, func(b []byte) error {
		select {
		case toAgent <- append([]byte(nil), b...):
			return nil
		case <-ctx.Done():
			return io.EOF
		}
	})
	return c, done
}

func TestSession(t *testing.T) {
	root := t.TempDir()
	deny := filepath.Join(root, "agent")
	os.MkdirAll(filepath.Join(deny, "keys"), 0o700)
	os.WriteFile(filepath.Join(deny, "keys", "agent.key"), []byte("secret"), 0o600)
	os.Mkdir(filepath.Join(root, "docs"), 0o755)
	c, done := pair(t, Options{MaxBytes: 8 << 20, Deny: []string{deny}, Idle: time.Minute})
	ctx := context.Background()

	if r, sep, err := c.Roots(ctx); err != nil || len(r) == 0 || sep == "" {
		t.Fatalf("roots %v %q %v", r, sep, err)
	}
	// Upload a file larger than the window, then download it.
	big := make([]byte, ChunkSize*(Window+3)+123)
	rand.Read(big)
	target := filepath.Join(root, "docs", "big.bin")
	sum, err := c.Put(ctx, target, int64(len(big)), false, bytes.NewReader(big))
	if err != nil || sum == "" {
		t.Fatalf("put: %v", err)
	}
	if got, _ := os.ReadFile(target); !bytes.Equal(got, big) {
		t.Fatal("uploaded content differs")
	}
	if _, err := c.Put(ctx, target, 3, false, strings.NewReader("abc")); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("overwrite without consent: %v", err)
	}
	if _, err := c.Put(ctx, target, 3, true, strings.NewReader("abc")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if _, err := c.Put(ctx, target, 3, true, strings.NewReader("ab")); err == nil {
		t.Fatal("short upload accepted")
	}
	if got, _ := os.ReadFile(target); string(got) != "abc" {
		t.Fatalf("file after a failed upload: %q", got)
	}
	// The cancelled upload's temporary file goes away.
	for i := 0; ; i++ {
		entries, _ := os.ReadDir(filepath.Join(root, "docs"))
		if len(entries) == 1 {
			break
		}
		if i == 100 {
			t.Fatalf("leftovers: %v", entries)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := c.Put(ctx, filepath.Join(root, "docs", "huge"), 9<<20, false, bytes.NewReader(make([]byte, 9<<20))); err == nil {
		t.Fatal("over the limit accepted")
	}
	os.WriteFile(filepath.Join(root, "docs", "big2.bin"), big, 0o644)
	var buf bytes.Buffer
	var announced int64
	n, _, err := c.Get(ctx, filepath.Join(root, "docs", "big2.bin"), &buf, func(s int64) { announced = s })
	if err != nil || n != int64(len(big)) || announced != n || !bytes.Equal(buf.Bytes(), big) {
		t.Fatalf("get: %d %d %v", n, announced, err)
	}
	// Listing, folders, denied paths.
	if err := c.Mkdir(ctx, filepath.Join(root, "docs", "new")); err != nil {
		t.Fatal(err)
	}
	l, err := c.List(ctx, filepath.Join(root, "docs"))
	if err != nil || len(l.Entries) != 3 || !l.Entries[0].Dir || l.Entries[0].Name != "new" {
		t.Fatalf("list: %+v %v", l, err)
	}
	for _, p := range []string{filepath.Join(deny, "keys", "agent.key"), filepath.Join(root, "docs", "..", "agent", "keys", "agent.key")} {
		if _, _, err := c.Get(ctx, p, io.Discard, nil); err == nil {
			t.Fatalf("denied file read: %s", p)
		}
	}
	if _, err := c.List(ctx, "relative"); err == nil {
		t.Fatal("relative path accepted")
	}
	os.Symlink(deny, filepath.Join(root, "docs", "link"))
	if _, err := c.List(ctx, filepath.Join(root, "docs", "link")); err == nil {
		t.Fatal("denied folder through a link")
	}
	c.Close()
	st := <-done
	if st.Uploads != 2 || st.Downloads != 1 || st.BytesOut != int64(len(big)) {
		t.Fatalf("stats %+v", st)
	}
}
