//go:build windows

package secfile

import (
	"os"

	"golang.org/x/sys/windows"
)

// protectedSDDL grants full control to LocalSystem and Administrators only,
// inherited by files and subfolders, and blocks inheritance from the parent.
const protectedSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func restrictDir(dir string) error {
	return applySDDL(dir)
}

// restrictFile is a no-op: files created in a restricted directory inherit
// its protected DACL.
func restrictFile(*os.File) error { return nil }

func applySDDL(path string) error {
	sd, err := windows.SecurityDescriptorFromString(protectedSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}
