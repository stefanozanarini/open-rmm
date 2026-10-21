// Package winver corrects the Windows version names reported by the
// registry.
package winver

import (
	"regexp"
	"strconv"
	"strings"
)

// Windows 11 kept the Windows 10 product name in the registry
// (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName): builds
// from 22000 on are Windows 11 whatever it says.
const firstWindows11Build = 22000

var buildRe = regexp.MustCompile(`\(build (\d+)`)

// Fix corrects an OS description such as "Windows 10 Pro 25H2 (build
// 26200.9711)": with a Windows 11 build, "Windows 10" becomes "Windows 11".
// Other descriptions are returned unchanged.
func Fix(desc string) string {
	m := buildRe.FindStringSubmatch(desc)
	if m == nil {
		return desc
	}
	if build, err := strconv.Atoi(m[1]); err != nil || build < firstWindows11Build {
		return desc
	}
	return strings.Replace(desc, "Windows 10", "Windows 11", 1)
}
