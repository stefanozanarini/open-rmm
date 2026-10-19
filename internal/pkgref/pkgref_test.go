package pkgref

import (
	"testing"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
)

func TestValidFileName(t *testing.T) {
	for _, ok := range []string{"7z2408-x64.msi", "Firefox Setup 131.0.exe", "npp.8.7.Installer.x64.exe"} {
		if !ValidFileName(ok) {
			t.Errorf("refused %q", ok)
		}
	}
	for _, bad := range []string{"../x.msi", `a\b.msi`, "a/b.msi", ".hidden.msi", "noext", "CON.msi", "x..msi", "a.msi ", ""} {
		if ValidFileName(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestValidate(t *testing.T) {
	ref := func(name string) *openrmmv1.PackageRef {
		return &openrmmv1.PackageRef{Sha256: make([]byte, 32), FileName: name, Size: 10}
	}
	if err := Validate([]*openrmmv1.PackageRef{ref("a.msi"), ref("b.msi")}); err != nil {
		t.Fatal(err)
	}
	if Validate([]*openrmmv1.PackageRef{ref("a.msi"), ref("A.MSI")}) == nil {
		t.Fatal("duplicate names accepted")
	}
	if Validate([]*openrmmv1.PackageRef{{Sha256: []byte{1}, FileName: "a.msi", Size: 1}}) == nil {
		t.Fatal("short hash accepted")
	}
}
