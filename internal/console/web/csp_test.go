package web

import (
	"io/fs"
	"regexp"
	"testing"
)

// The Content-Security-Policy blocks inline scripts and styles: an inline
// handler or style attribute in a template silently does nothing.
func TestTemplatesHaveNoInlineScriptsOrStyles(t *testing.T) {
	inline := regexp.MustCompile(`(?i)\son[a-z]+\s*=|\sstyle\s*=|<script[^>]*>[^<]|<style`)
	names, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		b, err := fs.ReadFile(assets, n)
		if err != nil {
			t.Fatal(err)
		}
		if m := inline.Find(b); m != nil {
			t.Errorf("%s: inline script or style %q", n, m)
		}
	}
}
