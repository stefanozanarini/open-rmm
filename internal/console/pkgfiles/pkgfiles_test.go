package pkgfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

func TestSaveOpen(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	sum, n, err := d.Save(strings.NewReader("hello"), 10)
	want := sha256.Sum256([]byte("hello"))
	if err != nil || n != 5 || sum != hex.EncodeToString(want[:]) {
		t.Fatal(sum, n, err)
	}
	f, err := d.Open(sum)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "hello" {
		t.Fatal(string(b))
	}
	if _, _, err := d.Save(strings.NewReader("0123456789x"), 10); err != ErrTooLarge {
		t.Fatalf("too large: %v", err)
	}
	if _, err := d.Open("../etc/passwd"); err == nil {
		t.Fatal("path accepted")
	}
}
