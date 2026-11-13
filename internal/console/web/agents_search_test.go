package web

import (
	"net/netip"
	"testing"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
)

func TestAgentRowMatches(t *testing.T) {
	ip := netip.MustParseAddr("10.20.30.40")
	r := agentRow{Agent: store.Agent{ID: "7b3023db-7da1", LastSeenIP: &ip,
		Host: store.HostInfo{Hostname: "FR010009L", OSVersion: "Windows 11 Pro 26H2", AgentVersion: "1.0.2"}},
		Inv: store.InventorySummary{Model: "Latitude 5440", IPv4: []string{"192.168.76.15"}}, Site: "Datacenter",
		User: userView{Name: `CORP\mario.rossi`}, UserNames: []string{"Mario Rossi", "Mario", "Rossi"}}
	for q, want := range map[string]bool{
		"fr010009l": true, "192.168.76.15": true, "192.168.76": true, "10.20.30.40": true, "7b3023db": true,
		"1.0.2": true, "fr01 26h2": true, "fr01 latitude datacenter": true, "fr01 25h2": false, "172.16.": false,
		"fr01*": true, "fr*9l": true, "*009l": true, "*0009*": true, "fr01*x": false, "01*": false, "*": true,
		"mario.rossi": true, "mario*": true, `corp\mario*`: true, "*rossi": true, "rossi*": true, "mario rossi": true, "rossi mario": true, "verdi": false, "corp\\luigi": false,
	} {
		if got := r.matches(q); got != want {
			t.Errorf("matches(%q) = %v, want %v", q, got, want)
		}
	}
}
