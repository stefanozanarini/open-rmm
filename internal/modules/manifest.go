// Package modules defines signed open-rmm modules: the manifest, the bundle
// distributed to agents, and safe packing and extraction of the archive.
//
// Trust chain: the module release key (kept offline) signs the manifest; the
// manifest pins the SHA-256 of the archive and of every file in it; a job
// pins the SHA-256 of the signed manifest bytes.
package modules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// ProtocolVersion is the core↔module protocol implemented by this agent.
const ProtocolVersion = 1

// Entrypoint types.
const (
	TypePowerShell = "powershell" // Windows PowerShell 5.1, or pwsh where that is absent
	TypeBinary     = "binary"     // native executable
	TypeShell      = "sh"         // POSIX shell script (Linux)
)

// Capabilities a module may declare. They let local policy refuse whole
// classes of modules regardless of what the console asks.
const (
	CapAdHocScript = "adhoc_script" // runs arbitrary code supplied in the job
)

// Execution contexts.
const (
	ContextSystem = "system"
	// ContextUser runs in the logged-on user's session through the user
	// helper (not implemented yet).
	ContextUser = "user"
)

const (
	MaxActionTimeout     = 4 * time.Hour
	DefaultActionTimeout = 10 * time.Minute
	maxFiles             = 512
)

var (
	idRe      = regexp.MustCompile(`^[a-z][a-z0-9-]{1,40}$`)
	versionRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	actionRe  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,40}$`)
	// platformRe matches GOOS/GOARCH.
	platformRe = regexp.MustCompile(`^(windows|linux)/(amd64|arm64|386)$`)
)

// Manifest describes a module version.
type Manifest struct {
	ID              string                `json:"id"`
	Version         string                `json:"version"`
	Description     string                `json:"description,omitempty"`
	ProtocolVersion int                   `json:"protocol_version"`
	Entrypoints     map[string]Entrypoint `json:"entrypoints"` // by GOOS/GOARCH
	Actions         map[string]Action     `json:"actions"`
	Capabilities    []string              `json:"capabilities,omitempty"`
	// Filled in by Pack.
	ArchiveSHA256 string `json:"archive_sha256"`
	Files         []File `json:"files"`
}

// Entrypoint is what the agent runs on one platform.
type Entrypoint struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// Action is one operation offered by the module.
type Action struct {
	Description    string `json:"description,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	Context        string `json:"context,omitempty"`
}

// File is one archive member with its hash.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ValidID reports whether s is a valid module identifier.
func ValidID(s string) bool { return idRe.MatchString(s) }

// ValidVersion reports whether s is a valid module version (x.y.z).
func ValidVersion(s string) bool { return versionRe.MatchString(s) }

// Timeout returns the effective timeout of an action.
func (a Action) Timeout() time.Duration {
	if a.TimeoutSeconds <= 0 {
		return DefaultActionTimeout
	}
	return time.Duration(a.TimeoutSeconds) * time.Second
}

// HasCapability reports whether the module declares c.
func (m *Manifest) HasCapability(c string) bool {
	for _, x := range m.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// Validate checks the static parts of a manifest. complete requires the
// fields filled in by Pack.
func (m *Manifest) Validate(complete bool) error {
	if !ValidID(m.ID) {
		return fmt.Errorf("invalid module id %q", m.ID)
	}
	if !ValidVersion(m.Version) {
		return fmt.Errorf("invalid module version %q", m.Version)
	}
	if m.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("unsupported protocol_version %d", m.ProtocolVersion)
	}
	if len(m.Description) > 500 {
		return errors.New("description too long")
	}
	if len(m.Entrypoints) == 0 {
		return errors.New("at least one entrypoint is required")
	}
	for p, e := range m.Entrypoints {
		if !platformRe.MatchString(p) {
			return fmt.Errorf("invalid platform %q", p)
		}
		switch e.Type {
		case TypePowerShell, TypeBinary, TypeShell:
		default:
			return fmt.Errorf("platform %s: invalid entrypoint type %q", p, e.Type)
		}
		if err := validPath(e.Path); err != nil {
			return fmt.Errorf("platform %s: %w", p, err)
		}
	}
	if len(m.Actions) == 0 {
		return errors.New("at least one action is required")
	}
	for name, a := range m.Actions {
		if !actionRe.MatchString(name) {
			return fmt.Errorf("invalid action name %q", name)
		}
		if a.TimeoutSeconds < 0 || a.Timeout() > MaxActionTimeout {
			return fmt.Errorf("action %s: timeout must be at most %s", name, MaxActionTimeout)
		}
		switch a.Context {
		case "", ContextSystem, ContextUser:
		default:
			return fmt.Errorf("action %s: invalid context %q", name, a.Context)
		}
	}
	for _, c := range m.Capabilities {
		if c != CapAdHocScript {
			return fmt.Errorf("unknown capability %q", c)
		}
	}
	if !complete {
		return nil
	}
	if b, err := hex.DecodeString(m.ArchiveSHA256); err != nil || len(b) != sha256.Size {
		return errors.New("invalid archive_sha256")
	}
	if len(m.Files) == 0 || len(m.Files) > maxFiles {
		return fmt.Errorf("a module must contain 1-%d files", maxFiles)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if err := validPath(f.Path); err != nil {
			return err
		}
		key := strings.ToLower(f.Path) // Windows file systems are case-insensitive
		if seen[key] {
			return fmt.Errorf("duplicate file %q", f.Path)
		}
		seen[key] = true
		if b, err := hex.DecodeString(f.SHA256); err != nil || len(b) != sha256.Size {
			return fmt.Errorf("file %s: invalid sha256", f.Path)
		}
		if f.Size < 0 || f.Size > maxFileSize {
			return fmt.Errorf("file %s: invalid size", f.Path)
		}
	}
	for p, e := range m.Entrypoints {
		if !seen[strings.ToLower(e.Path)] {
			return fmt.Errorf("platform %s: entrypoint %s is not in the archive", p, e.Path)
		}
	}
	return nil
}

// validPath accepts relative, clean, forward-slash paths made of safe
// characters, so that the same path is safe on Windows and Linux.
func validPath(p string) error {
	if p == "" || len(p) > 200 {
		return fmt.Errorf("invalid path %q", p)
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, `\`) || strings.Contains(p, ":") || path.Clean(p) != p {
		return fmt.Errorf("path %q must be relative and clean", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." || seg == "" || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return fmt.Errorf("invalid path %q", p)
		}
		for _, r := range seg {
			ok := r == '-' || r == '_' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !ok {
				return fmt.Errorf("path %q contains unsupported characters", p)
			}
		}
	}
	return nil
}

// ParseManifest decodes and validates a complete manifest.
func ParseManifest(raw []byte) (*Manifest, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	m := &Manifest{}
	if err := dec.Decode(m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if err := m.Validate(true); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return m, nil
}

// ManifestHash is the value a job pins: SHA-256 of the signed manifest bytes.
func ManifestHash(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}
