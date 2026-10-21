package winver

import "testing"

func TestFix(t *testing.T) {
	for in, want := range map[string]string{
		"Windows 10 Pro 25H2 (build 26200.9711)":           "Windows 11 Pro 25H2 (build 26200.9711)",
		"Windows 10 Enterprise 22H2 (build 19045.5011)":    "Windows 10 Enterprise 22H2 (build 19045.5011)",
		"Windows Server 2019 Standard  (build 17763.9376)": "Windows Server 2019 Standard  (build 17763.9376)",
		"Windows 11 Pro 24H2 (build 26100.2605)":           "Windows 11 Pro 24H2 (build 26100.2605)",
		"Ubuntu 26.04":                                     "Ubuntu 26.04",
	} {
		if got := Fix(in); got != want {
			t.Errorf("Fix(%q) = %q, want %q", in, got, want)
		}
	}
}
