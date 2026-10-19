//go:build linux

package pty

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestShellOnPTY(t *testing.T) {
	p, err := Start([]string{"/bin/sh", "-i"}, []string{"PATH=/usr/bin:/bin", "PS1=$ ", "TERM=xterm"}, "/", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.Write([]byte("stty size; echo hello-$((40+2))\n")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := p.Read(buf)
			out.Write(buf[:n])
			if err != nil || strings.Contains(out.String(), "hello-42") {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("no output: %q", out.String())
	}
	if !strings.Contains(out.String(), "24 80") {
		t.Fatalf("terminal size not applied: %q", out.String())
	}
	if err := p.Resize(100, 40); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if _, err := p.Read(make([]byte, 10)); err == nil {
		t.Fatal("read after close")
	}
}
