// Package modcache downloads, verifies and caches modules on the agent.
//
// Layout under <data>/modules:
//
//	<id>/<version>-<first 16 hex of manifest hash>/
//	    manifest.json        signed manifest bytes
//	    manifest.sig.json    key id and signature
//	    files/...            extracted archive
//
// A cache entry is re-verified (signature and file hashes) every time it is
// used, so tampering with the cache is detected before anything runs.
package modcache

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/stefanozanarini/open-rmm/internal/agent/secfile"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// Fetched is what a Fetcher returns: the signed manifest and the archive.
type Fetched struct {
	KeyID     string
	Manifest  []byte
	Signature []byte
	Archive   []byte
}

// Fetcher downloads a module version from the console.
type Fetcher interface {
	FetchModule(ctx context.Context, id, version string) (*Fetched, error)
}

// Installed is a verified module ready to run.
type Installed struct {
	Manifest *modules.Manifest
	// FilesDir holds the extracted archive.
	FilesDir string
}

// Cache is the agent's module store.
type Cache struct {
	dir  string
	keys *signing.Keyring
	mu   sync.Mutex // serializes installs
}

// New returns a cache rooted at <dataDir>/modules.
func New(dataDir string, keys *signing.Keyring) (*Cache, error) {
	dir := filepath.Join(dataDir, "modules")
	if err := secfile.EnsureDir(dir); err != nil {
		return nil, err
	}
	return &Cache{dir: dir, keys: keys}, nil
}

type sigFile struct {
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

// Get returns the module pinned by manifestHash, downloading it if needed.
func (c *Cache) Get(ctx context.Context, f Fetcher, id, version string, manifestHash []byte) (*Installed, error) {
	if !modules.ValidID(id) || !modules.ValidVersion(version) || len(manifestHash) != 32 {
		return nil, errors.New("invalid module reference")
	}
	if c.keys.Len() == 0 {
		return nil, errors.New("no module signing keys configured")
	}
	entry := filepath.Join(c.dir, id, version+"-"+hex.EncodeToString(manifestHash[:8]))
	c.mu.Lock()
	defer c.mu.Unlock()
	if inst, err := c.load(entry, id, version, manifestHash); err == nil {
		return inst, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		// A damaged or tampered entry is discarded and downloaded again.
		if rmErr := os.RemoveAll(entry); rmErr != nil {
			return nil, fmt.Errorf("discard bad cache entry: %w (after: %v)", rmErr, err)
		}
	}
	got, err := f.FetchModule(ctx, id, version)
	if err != nil {
		return nil, fmt.Errorf("download module %s %s: %w", id, version, err)
	}
	v, err := modules.VerifyManifest(c.keys, got.KeyID, got.Manifest, got.Signature)
	if err != nil {
		return nil, err
	}
	if err := checkRef(v.Manifest, id, version, v.ManifestHash, manifestHash); err != nil {
		return nil, err
	}
	if err := secfile.EnsureDir(filepath.Dir(entry)); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(entry), ".install-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := modules.Extract(v.Manifest, got.Archive, filepath.Join(tmp, "files")); err != nil {
		return nil, err
	}
	sig, err := json.Marshal(sigFile{KeyID: got.KeyID, Signature: got.Signature})
	if err != nil {
		return nil, err
	}
	if err := secfile.WriteFile(filepath.Join(tmp, "manifest.json"), got.Manifest); err != nil {
		return nil, err
	}
	if err := secfile.WriteFile(filepath.Join(tmp, "manifest.sig.json"), sig); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, entry); err != nil {
		return nil, err
	}
	return &Installed{Manifest: v.Manifest, FilesDir: filepath.Join(entry, "files")}, nil
}

func (c *Cache) load(entry, id, version string, manifestHash []byte) (*Installed, error) {
	raw, err := os.ReadFile(filepath.Join(entry, "manifest.json")) // #nosec G304 -- inside the agent data dir
	if err != nil {
		return nil, err
	}
	sraw, err := os.ReadFile(filepath.Join(entry, "manifest.sig.json")) // #nosec G304 -- inside the agent data dir
	if err != nil {
		return nil, err
	}
	var sf sigFile
	if err := json.Unmarshal(sraw, &sf); err != nil {
		return nil, fmt.Errorf("cache signature file: %w", err)
	}
	v, err := modules.VerifyManifest(c.keys, sf.KeyID, raw, sf.Signature)
	if err != nil {
		return nil, err
	}
	if err := checkRef(v.Manifest, id, version, v.ManifestHash, manifestHash); err != nil {
		return nil, err
	}
	files := filepath.Join(entry, "files")
	if err := modules.VerifyFiles(v.Manifest, files); err != nil {
		return nil, err
	}
	return &Installed{Manifest: v.Manifest, FilesDir: files}, nil
}

func checkRef(m *modules.Manifest, id, version string, got, want []byte) error {
	if m.ID != id || m.Version != version {
		return fmt.Errorf("console sent module %s %s instead of %s %s", m.ID, m.Version, id, version)
	}
	if !bytes.Equal(got, want) {
		return errors.New("module manifest does not match the hash pinned by the job")
	}
	return nil
}
