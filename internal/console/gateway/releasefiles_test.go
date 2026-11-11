package gateway

import (
	"context"
	"testing"
)

// Release files are loaded once and shared; downloads beyond the limit wait.
func TestReleaseFiles(t *testing.T) {
	var rf releaseFiles
	loads := 0
	load := func() ([]byte, error) { loads++; return []byte("exe"), nil }
	for i := 0; i < 5; i++ {
		if b, err := rf.get("1.1.0", "windows/amd64", "openrmm-agent.exe", load); err != nil || string(b) != "exe" {
			t.Fatal(b, err)
		}
	}
	if loads != 1 {
		t.Fatalf("loaded %d times", loads)
	}
	for i := 0; i < releaseConcurrent; i++ {
		if !rf.acquire(context.Background()) {
			t.Fatal("slot refused")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rf.acquire(ctx) {
		t.Fatal("slot beyond the limit")
	}
	rf.release()
	if !rf.acquire(context.Background()) {
		t.Fatal("freed slot refused")
	}
}
