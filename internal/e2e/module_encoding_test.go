package e2e

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Windows PowerShell 5.1 reads a script without a byte order mark in the
// ANSI code page: "più" becomes "piÃ¹" in what the module reports and in
// the notices shown to users. Scripts with non-ASCII text carry a UTF-8 BOM.
func TestModuleScriptsDeclareUTF8(t *testing.T) {
	root := filepath.Join(repoRoot(t), "modules")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(path, ".ps1") || strings.HasSuffix(path, ".psm1") || strings.HasSuffix(path, ".psd1")) {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		ascii := true
		for _, c := range b {
			if c >= 0x80 {
				ascii = false
				break
			}
		}
		if !ascii && !bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
			t.Errorf("%s: non-ASCII text without a UTF-8 byte order mark", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
