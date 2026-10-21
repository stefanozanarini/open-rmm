//go:build linux

package pty

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
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

func TestEnvBlock(t *testing.T) {
	b, err := envBlock([]string{"A=1", "PATH=C:\\Windows", "È=ü"})
	if err != nil {
		t.Fatal(err)
	}
	want := append(append(append(utf16.Encode([]rune("A=1")), 0), append(utf16.Encode([]rune("PATH=C:\\Windows")), 0)...), append(utf16.Encode([]rune("È=ü")), 0, 0)...)
	if !slices.Equal(b, want) {
		t.Fatalf("block = %v", b)
	}
	if b, _ := envBlock(nil); !slices.Equal(b, []uint16{0, 0}) {
		t.Fatalf("empty block = %v", b)
	}
	for _, bad := range []string{"A=1\x00B=2", "NOEQUALS"} {
		if _, err := envBlock([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
