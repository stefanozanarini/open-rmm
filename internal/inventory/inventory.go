// Package inventory defines the hardware and software inventory reported by
// the inventory module, normalizes what agents send and computes the changes
// between two inventories.
//
// The console never trusts the shape of agent data: Parse decodes only known
// fields, clips strings and bounds lists, and the console stores the
// re-encoded result.
package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Module and action whose results are inventories.
const (
	ModuleID = "inventory"
	Action   = "collect"
	Schema   = 1
)

const (
	maxString   = 512
	maxSoftware = 5000
	maxItems    = 256
	maxAddrs    = 32
)

// Inventory is one snapshot of an endpoint.
type Inventory struct {
	Schema       int          `json:"schema"`
	CollectedAt  time.Time    `json:"collected_at"`
	System       System       `json:"system"`
	OS           OS           `json:"os"`
	Firmware     Firmware     `json:"firmware"`
	CPUs         []CPU        `json:"cpus,omitempty"`
	Memory       Memory       `json:"memory"`
	Disks        []Disk       `json:"disks,omitempty"`
	Volumes      []Volume     `json:"volumes,omitempty"`
	Network      []NIC        `json:"network,omitempty"`
	TPM          TPM          `json:"tpm"`
	Batteries    []Battery    `json:"batteries,omitempty"`
	Monitors     []Monitor    `json:"monitors,omitempty"`
	Software     []Software   `json:"software,omitempty"`
	RemoteAccess RemoteAccess `json:"remote_access"`
}

type System struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	SKU          string `json:"sku,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Chassis      string `json:"chassis,omitempty"`
	Domain       string `json:"domain,omitempty"`
	PartOfDomain bool   `json:"part_of_domain,omitempty"`
	Virtual      bool   `json:"virtual,omitempty"`
}

type OS struct {
	Name             string     `json:"name,omitempty"`
	Version          string     `json:"version,omitempty"`
	Build            string     `json:"build,omitempty"`
	DisplayVersion   string     `json:"display_version,omitempty"` // e.g. 24H2
	Family           string     `json:"family,omitempty"`          // client | server
	InstallationType string     `json:"installation_type,omitempty"`
	Architecture     string     `json:"architecture,omitempty"`
	InstallDate      *time.Time `json:"install_date,omitempty"`
	LastBoot         *time.Time `json:"last_boot,omitempty"`
	LoggedOnUser     string     `json:"logged_on_user,omitempty"`
}

type Firmware struct {
	Vendor     string `json:"vendor,omitempty"`
	Version    string `json:"version,omitempty"`
	Date       string `json:"date,omitempty"`
	UEFI       *bool  `json:"uefi,omitempty"`
	SecureBoot *bool  `json:"secure_boot,omitempty"`
}

type CPU struct {
	Name    string `json:"name,omitempty"`
	Cores   int    `json:"cores,omitempty"`
	Threads int    `json:"threads,omitempty"`
}

type Memory struct {
	TotalBytes int64       `json:"total_bytes,omitempty"`
	Modules    []MemModule `json:"modules,omitempty"`
}

type MemModule struct {
	Slot         string `json:"slot,omitempty"`
	CapacityByte int64  `json:"capacity_bytes,omitempty"`
	SpeedMHz     int    `json:"speed_mhz,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	PartNumber   string `json:"part_number,omitempty"`
	Serial       string `json:"serial,omitempty"`
}

type Disk struct {
	Model     string `json:"model,omitempty"`
	Serial    string `json:"serial,omitempty"`
	MediaType string `json:"media_type,omitempty"` // SSD | HDD
	Bus       string `json:"bus,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	Health    string `json:"health,omitempty"` // Healthy | Warning | Unhealthy
}

type Volume struct {
	Mount      string `json:"mount,omitempty"`
	Label      string `json:"label,omitempty"`
	FS         string `json:"fs,omitempty"`
	SizeBytes  int64  `json:"size_bytes,omitempty"`
	FreeBytes  int64  `json:"free_bytes,omitempty"`
	BitLocker  string `json:"bitlocker,omitempty"` // on | off | encrypting | decrypting | suspended
	Encryption string `json:"encryption,omitempty"`
}

type NIC struct {
	Name    string   `json:"name,omitempty"`
	MAC     string   `json:"mac,omitempty"`
	IPv4    []string `json:"ipv4,omitempty"`
	IPv6    []string `json:"ipv6,omitempty"`
	Gateway []string `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
	DHCP    bool     `json:"dhcp,omitempty"`
}

type TPM struct {
	Present bool   `json:"present,omitempty"`
	Ready   bool   `json:"ready,omitempty"`
	Version string `json:"version,omitempty"`
}

type Battery struct {
	Name               string `json:"name,omitempty"`
	DesignCapacity     int64  `json:"design_capacity,omitempty"`
	FullChargeCapacity int64  `json:"full_charge_capacity,omitempty"`
	HealthPercent      int    `json:"health_percent,omitempty"`
	ChargePercent      int    `json:"charge_percent,omitempty"`
	CycleCount         int    `json:"cycle_count,omitempty"`
}

type Monitor struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
}

// Software is an installed application.
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
	Arch        string `json:"arch,omitempty"`  // x64 | x86
	Scope       string `json:"scope,omitempty"` // machine | user
	ProductCode string `json:"product_code,omitempty"`
	// QuietUninstall reports a registered silent uninstall command, used to
	// decide how the application can be removed from the console.
	QuietUninstall  bool `json:"quiet_uninstall,omitempty"`
	SystemComponent bool `json:"system_component,omitempty"`
}

// RemoteAccess holds the ids of remote support tools installed.
type RemoteAccess struct {
	SupremoID    string `json:"supremo_id,omitempty"`
	AnyDeskID    string `json:"anydesk_id,omitempty"`
	TeamViewerID string `json:"teamviewer_id,omitempty"`
}

// Parse decodes an inventory returned by the module and normalizes it.
func Parse(raw []byte) (*Inventory, error) {
	inv := &Inventory{}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(inv); err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	if inv.Schema != Schema {
		return nil, fmt.Errorf("inventory: unsupported schema %d", inv.Schema)
	}
	if inv.CollectedAt.IsZero() {
		return nil, errors.New("inventory: collected_at missing")
	}
	inv.normalize()
	return inv, nil
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > maxString {
		s = s[:maxString]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func clipAll(ss []string, n int) []string {
	if len(ss) > n {
		ss = ss[:n]
	}
	var out []string
	for _, s := range ss {
		if s = clip(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func bound[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// digits keeps only digits; ids shorter than 6 or longer than 16 digits are
// not valid ids for Supremo, AnyDesk or TeamViewer.
func digits(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
	if len(s) < 6 || len(s) > 16 {
		return ""
	}
	return s
}

func nonNeg(n int64) int64 { return max(n, 0) }

func (inv *Inventory) normalize() {
	inv.CollectedAt = inv.CollectedAt.UTC()
	s := &inv.System
	s.Manufacturer, s.Model, s.SKU, s.Serial = clip(s.Manufacturer), clip(s.Model), clip(s.SKU), clip(s.Serial)
	s.Chassis, s.Domain = clip(s.Chassis), clip(s.Domain)
	o := &inv.OS
	o.Name, o.Version, o.Build, o.DisplayVersion = clip(o.Name), clip(o.Version), clip(o.Build), clip(o.DisplayVersion)
	o.InstallationType, o.Architecture, o.LoggedOnUser = clip(o.InstallationType), clip(o.Architecture), clip(o.LoggedOnUser)
	if o.Family != "client" && o.Family != "server" {
		o.Family = ""
	}
	f := &inv.Firmware
	f.Vendor, f.Version, f.Date = clip(f.Vendor), clip(f.Version), clip(f.Date)

	inv.CPUs = bound(inv.CPUs, maxItems)
	for i := range inv.CPUs {
		inv.CPUs[i].Name = clip(inv.CPUs[i].Name)
	}
	inv.Memory.TotalBytes = nonNeg(inv.Memory.TotalBytes)
	inv.Memory.Modules = bound(inv.Memory.Modules, maxItems)
	for i := range inv.Memory.Modules {
		m := &inv.Memory.Modules[i]
		m.Slot, m.Manufacturer, m.PartNumber, m.Serial = clip(m.Slot), clip(m.Manufacturer), clip(m.PartNumber), clip(m.Serial)
		m.CapacityByte = nonNeg(m.CapacityByte)
	}
	inv.Disks = bound(inv.Disks, maxItems)
	for i := range inv.Disks {
		d := &inv.Disks[i]
		d.Model, d.Serial, d.MediaType, d.Bus, d.Health = clip(d.Model), clip(d.Serial), clip(d.MediaType), clip(d.Bus), clip(d.Health)
		d.SizeBytes = nonNeg(d.SizeBytes)
	}
	inv.Volumes = bound(inv.Volumes, maxItems)
	for i := range inv.Volumes {
		v := &inv.Volumes[i]
		v.Mount, v.Label, v.FS, v.BitLocker, v.Encryption = clip(v.Mount), clip(v.Label), clip(v.FS), clip(v.BitLocker), clip(v.Encryption)
		v.SizeBytes, v.FreeBytes = nonNeg(v.SizeBytes), nonNeg(v.FreeBytes)
	}
	inv.Network = bound(inv.Network, maxItems)
	for i := range inv.Network {
		n := &inv.Network[i]
		n.Name, n.MAC = clip(n.Name), clip(n.MAC)
		n.IPv4, n.IPv6 = clipAll(n.IPv4, maxAddrs), clipAll(n.IPv6, maxAddrs)
		n.Gateway, n.DNS = clipAll(n.Gateway, maxAddrs), clipAll(n.DNS, maxAddrs)
	}
	inv.TPM.Version = clip(inv.TPM.Version)
	inv.Batteries = bound(inv.Batteries, maxItems)
	for i := range inv.Batteries {
		b := &inv.Batteries[i]
		b.Name = clip(b.Name)
		b.DesignCapacity, b.FullChargeCapacity = nonNeg(b.DesignCapacity), nonNeg(b.FullChargeCapacity)
		b.HealthPercent, b.ChargePercent = max(0, min(b.HealthPercent, 200)), max(0, min(b.ChargePercent, 100))
	}
	inv.Monitors = bound(inv.Monitors, maxItems)
	for i := range inv.Monitors {
		m := &inv.Monitors[i]
		m.Manufacturer, m.Model, m.Serial = clip(m.Manufacturer), clip(m.Model), clip(m.Serial)
	}
	inv.Software = bound(inv.Software, maxSoftware)
	sw := inv.Software[:0]
	for _, x := range inv.Software {
		x.Name, x.Version, x.Publisher, x.InstallDate = clip(x.Name), clip(x.Version), clip(x.Publisher), clip(x.InstallDate)
		x.Arch, x.Scope, x.ProductCode = clip(x.Arch), clip(x.Scope), clip(x.ProductCode)
		if x.Name != "" {
			sw = append(sw, x)
		}
	}
	sort.Slice(sw, func(i, j int) bool {
		a, b := strings.ToLower(sw[i].Name), strings.ToLower(sw[j].Name)
		if a != b {
			return a < b
		}
		return sw[i].Version < sw[j].Version
	})
	inv.Software = sw
	r := &inv.RemoteAccess
	r.SupremoID, r.AnyDeskID, r.TeamViewerID = digits(r.SupremoID), digits(r.AnyDeskID), digits(r.TeamViewerID)
}

// VisibleSoftware returns the applications an operator normally cares
// about (system components hidden).
func (inv *Inventory) VisibleSoftware() []Software {
	var out []Software
	for _, s := range inv.Software {
		if !s.SystemComponent {
			out = append(out, s)
		}
	}
	return out
}

// IPv4 returns the IPv4 addresses of the adapters (at most 32).
func (inv *Inventory) IPv4() []string {
	var out []string
	for _, n := range inv.Network {
		for _, a := range n.IPv4 {
			if len(out) < 32 {
				out = append(out, a)
			}
		}
	}
	return out
}
