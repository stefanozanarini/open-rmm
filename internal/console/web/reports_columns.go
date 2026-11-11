package web

import (
	"strconv"
	"strings"
	"time"

	"github.com/stefanozanarini/tempra-rmm/internal/console/store"
	"github.com/stefanozanarini/tempra-rmm/internal/inventory"
)

// Inventory columns the operator may add to Reporting → Inventory (?col=…),
// shown and exported to CSV in this order.

type invColumn struct {
	Key   string
	Label string // catalog key
	value func(lang string, a store.Agent, inv *inventory.Inventory) string
}

func gb(n int64) string {
	if n <= 0 {
		return ""
	}
	return strconv.FormatFloat(float64(n)/(1<<30), 'f', 0, 64) + " GB"
}

func yesNo(lang string, b *bool) string {
	if b == nil {
		return ""
	}
	if *b {
		return tr(lang, "sì")
	}
	return tr(lang, "no")
}

func dateOf(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

// systemVolume is the volume of the system drive (C: or /).
func systemVolume(inv *inventory.Inventory) *inventory.Volume {
	for i, v := range inv.Volumes {
		if strings.EqualFold(strings.TrimRight(v.Mount, `\`), "C:") || v.Mount == "/" {
			return &inv.Volumes[i]
		}
	}
	return nil
}

func joinNonEmpty(parts []string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}

var invColumns = []invColumn{
	{"status", "Stato", func(lang string, a store.Agent, _ *inventory.Inventory) string {
		return labelText(lang, string(a.Status))
	}},
	{"agent_version", "Versione agente", func(_ string, a store.Agent, _ *inventory.Inventory) string { return a.Host.AgentVersion }},
	{"last_seen", "Ultimo contatto", func(_ string, a store.Agent, _ *inventory.Inventory) string {
		if a.LastSeenAt == nil {
			return ""
		}
		return a.LastSeenAt.UTC().Format("2006-01-02 15:04")
	}},
	{"manufacturer", "Produttore", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.System.Manufacturer }},
	{"serial", "Numero di serie", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.System.Serial }},
	{"chassis", "Tipo di chassis", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.System.Chassis }},
	{"virtual", "Virtuale", func(lang string, _ store.Agent, inv *inventory.Inventory) string {
		return yesNo(lang, &inv.System.Virtual)
	}},
	{"domain", "Dominio", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.System.Domain }},
	{"os_build", "Build", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.OS.Build }},
	{"os_arch", "Architettura", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.OS.Architecture }},
	{"os_install", "Sistema installato il", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return dateOf(inv.OS.InstallDate) }},
	{"last_boot", "Ultimo avvio", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		if inv.OS.LastBoot == nil {
			return ""
		}
		return inv.OS.LastBoot.UTC().Format("2006-01-02 15:04")
	}},
	{"bios", "Versione BIOS", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.Firmware.Version }},
	{"bios_date", "Data del BIOS", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.Firmware.Date }},
	{"secure_boot", "Secure Boot", func(lang string, _ store.Agent, inv *inventory.Inventory) string {
		return yesNo(lang, inv.Firmware.SecureBoot)
	}},
	{"tpm", "TPM", func(lang string, _ store.Agent, inv *inventory.Inventory) string {
		if !inv.TPM.Present {
			return tr(lang, "no")
		}
		return strings.TrimSpace(inv.TPM.Version)
	}},
	{"cpu", "Processore", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		if len(inv.CPUs) == 0 {
			return ""
		}
		return inv.CPUs[0].Name
	}},
	{"cores", "Core", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		n := 0
		for _, c := range inv.CPUs {
			n += c.Cores
		}
		if n == 0 {
			return ""
		}
		return strconv.Itoa(n)
	}},
	{"ram", "RAM", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return gb(inv.Memory.TotalBytes) }},
	{"disks", "Dischi", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		var parts []string
		for _, d := range inv.Disks {
			parts = append(parts, strings.TrimSpace(d.Model+" ("+joinNonEmpty([]string{d.MediaType, gb(d.SizeBytes)})+")"))
		}
		return strings.Join(parts, "; ")
	}},
	{"disk_health", "Stato dei dischi", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		var parts []string
		for _, d := range inv.Disks {
			parts = append(parts, d.Health)
		}
		return joinNonEmpty(parts)
	}},
	{"system_free", "Spazio libero sul disco di sistema", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		v := systemVolume(inv)
		if v == nil || v.SizeBytes <= 0 {
			return ""
		}
		return gb(v.FreeBytes) + " (" + strconv.Itoa(int(v.FreeBytes*100/v.SizeBytes)) + "%)"
	}},
	{"bitlocker", "BitLocker", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		if v := systemVolume(inv); v != nil {
			return v.BitLocker
		}
		return ""
	}},
	{"ipv4", "Indirizzi IP", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return strings.Join(inv.IPv4(), ", ") }},
	{"mac", "Indirizzi MAC", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		var parts []string
		for _, n := range inv.Network {
			parts = append(parts, n.MAC)
		}
		return joinNonEmpty(parts)
	}},
	{"battery", "Salute della batteria", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		var parts []string
		for _, b := range inv.Batteries {
			if b.HealthPercent > 0 {
				parts = append(parts, strconv.Itoa(b.HealthPercent)+"%")
			}
		}
		return strings.Join(parts, ", ")
	}},
	{"monitors", "Monitor", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		var parts []string
		for _, m := range inv.Monitors {
			parts = append(parts, strings.TrimSpace(m.Manufacturer+" "+m.Model))
		}
		return joinNonEmpty(parts)
	}},
	{"admins", "Amministratori locali", func(_ string, _ store.Agent, inv *inventory.Inventory) string {
		var parts []string
		for _, l := range inv.LocalAdmins {
			parts = append(parts, l.Name)
		}
		return strings.Join(parts, ", ")
	}},
	{"supremo", "ID Supremo", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.RemoteAccess.SupremoID }},
	{"anydesk", "ID AnyDesk", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.RemoteAccess.AnyDeskID }},
	{"teamviewer", "ID TeamViewer", func(_ string, _ store.Agent, inv *inventory.Inventory) string { return inv.RemoteAccess.TeamViewerID }},
}

// columnChoice is a column offered in the form.
type columnChoice struct {
	Key, Label string
	Selected   bool
}

// selectedColumns returns the catalog columns named in keys, in catalog
// order, and the choices for the form.
func selectedColumns(keys []string) ([]invColumn, []columnChoice) {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	var cols []invColumn
	var choices []columnChoice
	for _, c := range invColumns {
		choices = append(choices, columnChoice{Key: c.Key, Label: c.Label, Selected: want[c.Key]})
		if want[c.Key] {
			cols = append(cols, c)
		}
	}
	return cols, choices
}

// columnValues are a row's values of the columns (empty without inventory,
// except those from the agent record).
func columnValues(lang string, cols []invColumn, a store.Agent, inv *inventory.Inventory) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		if inv == nil {
			switch c.Key {
			case "status", "agent_version", "last_seen":
				out[i] = c.value(lang, a, &inventory.Inventory{})
			}
			continue
		}
		out[i] = c.value(lang, a, inv)
	}
	return out
}
