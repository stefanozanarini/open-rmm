// Package release defines signed agent releases.
//
// A release is the pair of core executables (agent and watchdog) for one
// platform, described by a manifest signed with the agent release key (kept
// offline, separate from the module and job keys).
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// File names inside a release, per OS.
func AgentFile(goos string) string    { return exe(goos, "openrmm-agent") }
func WatchdogFile(goos string) string { return exe(goos, "openrmm-watchdog") }

func exe(goos, name string) string {
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}

const MaxFileSize = 100 << 20

var platformRe = regexp.MustCompile(`^(windows|linux)/(amd64|arm64|386)$`)

// Manifest describes a release.
type Manifest struct {
	Version    string    `json:"version"`
	Platform   string    `json:"platform"` // GOOS/GOARCH
	ReleasedAt time.Time `json:"released_at"`
	Notes      string    `json:"notes,omitempty"`
	Files      []File    `json:"files"`
}

// File is one executable of the release.
type File struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Validate checks a manifest.
func (m *Manifest) Validate() error {
	if _, err := ParseVersion(m.Version); err != nil {
		return err
	}
	if !platformRe.MatchString(m.Platform) {
		return fmt.Errorf("invalid platform %q", m.Platform)
	}
	goos, _, _ := strings.Cut(m.Platform, "/")
	want := map[string]bool{AgentFile(goos): false, WatchdogFile(goos): false}
	if len(m.Files) != len(want) {
		return errors.New("a release contains exactly the agent and the watchdog")
	}
	for _, f := range m.Files {
		seen, ok := want[f.Name]
		if !ok || seen {
			return fmt.Errorf("unexpected file %q", f.Name)
		}
		want[f.Name] = true
		if b, err := hex.DecodeString(f.SHA256); err != nil || len(b) != sha256.Size {
			return fmt.Errorf("%s: invalid sha256", f.Name)
		}
		if f.Size <= 0 || f.Size > MaxFileSize {
			return fmt.Errorf("%s: invalid size", f.Name)
		}
	}
	return nil
}

// File returns the entry called name.
func (m *Manifest) File(name string) (File, bool) {
	for _, f := range m.Files {
		if f.Name == name {
			return f, true
		}
	}
	return File{}, false
}

// Sign signs a manifest.
func Sign(s *signing.Signer, m *Manifest) (raw, sig []byte, err error) {
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	raw, err = json.Marshal(m)
	if err != nil {
		return nil, nil, err
	}
	return raw, s.Sign(signing.DomainAgentRelease, raw), nil
}

// Verify checks the signature with the trusted release keys and parses.
func Verify(keys *signing.Keyring, keyID string, raw, sig []byte) (*Manifest, error) {
	if err := keys.Verify(signing.DomainAgentRelease, keyID, raw, sig); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	m := &Manifest{}
	if err := dec.Decode(m); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	return m, nil
}

// HashFile returns the manifest entry for data.
func HashFile(name string, data []byte) File {
	sum := sha256.Sum256(data)
	return File{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

// CheckFile verifies data against the manifest entry.
func (f File) CheckFile(data []byte) error {
	sum := sha256.Sum256(data)
	if int64(len(data)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
		return fmt.Errorf("%s does not match the release manifest", f.Name)
	}
	return nil
}

// Version is x.y.z.
type Version struct{ Major, Minor, Patch int }

var versionRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

// ParseVersion parses a release version (x.y.z, no suffixes).
func ParseVersion(s string) (Version, error) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("invalid version %q (want x.y.z)", s)
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return Version{a, b, c}, nil
}

// ParseRunning parses the version of a running binary. Development builds
// ("0.0.0-dev", "abc123-dirty") count as 0.0.0, so any release is newer.
func ParseRunning(s string) Version {
	base, _, _ := strings.Cut(strings.TrimPrefix(s, "v"), "-")
	v, err := ParseVersion(base)
	if err != nil {
		return Version{}
	}
	return v
}

// Less reports whether v < w.
func (v Version) Less(w Version) bool {
	if v.Major != w.Major {
		return v.Major < w.Major
	}
	if v.Minor != w.Minor {
		return v.Minor < w.Minor
	}
	return v.Patch < w.Patch
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }
