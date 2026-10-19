package inventory

import (
	"fmt"
	"strings"
)

// Change kinds.
const (
	ChangeSoftwareAdded   = "software.added"
	ChangeSoftwareRemoved = "software.removed"
	ChangeSoftwareUpdated = "software.updated"
	ChangeHardware        = "hardware"
	ChangeOS              = "os"
	ChangeFirmware        = "firmware"
	ChangeDiskHealth      = "disk.health"
	ChangeEncryption      = "encryption"
	ChangeRemoteAccess    = "remote_access"
)

// Change is one difference between two inventories.
type Change struct {
	Kind   string
	Detail string
}

const maxChanges = 500

// Diff lists what changed from old to cur. A nil old (first inventory)
// produces no changes.
func Diff(old, cur *Inventory) []Change {
	if old == nil || cur == nil {
		return nil
	}
	var out []Change
	add := func(kind, format string, args ...any) {
		if len(out) < maxChanges {
			out = append(out, Change{Kind: kind, Detail: fmt.Sprintf(format, args...)})
		}
	}
	str := func(kind, what, a, b string) {
		if a != b && (a != "" || b != "") {
			add(kind, "%s: %s → %s", what, orDash(a), orDash(b))
		}
	}

	str(ChangeOS, "sistema operativo", old.OS.Name, cur.OS.Name)
	str(ChangeOS, "build", old.OS.Build, cur.OS.Build)
	str(ChangeFirmware, "BIOS/UEFI", old.Firmware.Version, cur.Firmware.Version)
	if old.Firmware.SecureBoot != nil && cur.Firmware.SecureBoot != nil && *old.Firmware.SecureBoot != *cur.Firmware.SecureBoot {
		add(ChangeFirmware, "Secure Boot: %s → %s", onOff(*old.Firmware.SecureBoot), onOff(*cur.Firmware.SecureBoot))
	}
	str(ChangeHardware, "seriale", old.System.Serial, cur.System.Serial)
	str(ChangeHardware, "modello", old.System.Model, cur.System.Model)
	if old.Memory.TotalBytes != cur.Memory.TotalBytes && old.Memory.TotalBytes > 0 && cur.Memory.TotalBytes > 0 {
		add(ChangeHardware, "memoria: %s → %s", Bytes(old.Memory.TotalBytes), Bytes(cur.Memory.TotalBytes))
	}
	cpu := func(inv *Inventory) string {
		var n []string
		for _, c := range inv.CPUs {
			n = append(n, c.Name)
		}
		return strings.Join(n, ", ")
	}
	str(ChangeHardware, "CPU", cpu(old), cpu(cur))

	diskKey := func(d Disk) string { return d.Serial + "|" + d.Model }
	oldDisks := map[string]Disk{}
	for _, d := range old.Disks {
		oldDisks[diskKey(d)] = d
	}
	curDisks := map[string]bool{}
	for _, d := range cur.Disks {
		curDisks[diskKey(d)] = true
		o, ok := oldDisks[diskKey(d)]
		switch {
		case !ok:
			add(ChangeHardware, "disco aggiunto: %s %s (%s)", d.Model, d.Serial, Bytes(d.SizeBytes))
		case o.Health != d.Health && d.Health != "":
			add(ChangeDiskHealth, "disco %s: stato %s → %s", d.Model, orDash(o.Health), d.Health)
		}
	}
	for k, d := range oldDisks {
		if !curDisks[k] {
			add(ChangeHardware, "disco rimosso: %s %s", d.Model, d.Serial)
		}
	}

	oldVols := map[string]Volume{}
	for _, v := range old.Volumes {
		oldVols[v.Mount] = v
	}
	for _, v := range cur.Volumes {
		if o, ok := oldVols[v.Mount]; ok && o.BitLocker != v.BitLocker {
			add(ChangeEncryption, "BitLocker %s: %s → %s", v.Mount, orDash(o.BitLocker), orDash(v.BitLocker))
		}
	}

	str(ChangeRemoteAccess, "ID Supremo", old.RemoteAccess.SupremoID, cur.RemoteAccess.SupremoID)
	str(ChangeRemoteAccess, "ID AnyDesk", old.RemoteAccess.AnyDeskID, cur.RemoteAccess.AnyDeskID)
	str(ChangeRemoteAccess, "ID TeamViewer", old.RemoteAccess.TeamViewerID, cur.RemoteAccess.TeamViewerID)

	// Software, keyed by name, scope and architecture; versions compared.
	swKey := func(s Software) string { return strings.ToLower(s.Name) + "|" + s.Scope + "|" + s.Arch }
	oldSw := map[string]string{}
	for _, s := range old.Software {
		oldSw[swKey(s)] = s.Version
	}
	curSw := map[string]bool{}
	for _, s := range cur.Software {
		k := swKey(s)
		if curSw[k] {
			continue
		}
		curSw[k] = true
		v, ok := oldSw[k]
		switch {
		case !ok:
			add(ChangeSoftwareAdded, "%s %s", s.Name, s.Version)
		case v != s.Version:
			add(ChangeSoftwareUpdated, "%s: %s → %s", s.Name, orDash(v), orDash(s.Version))
		}
	}
	for _, s := range old.Software {
		if k := swKey(s); !curSw[k] {
			curSw[k] = true // report once
			add(ChangeSoftwareRemoved, "%s %s", s.Name, s.Version)
		}
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func onOff(b bool) string {
	if b {
		return "attivo"
	}
	return "disattivo"
}

// Bytes formats a size in binary units.
func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
