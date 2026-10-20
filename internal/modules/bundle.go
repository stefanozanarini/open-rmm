package modules

import (
	"errors"
	"fmt"

	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// Bundle is the distributable form of a module version: the signed manifest
// bytes and the archive. It is what `openrmm-admin module sign` writes and
// `module publish` uploads.
type Bundle struct {
	KeyID     string `json:"key_id"`
	Manifest  []byte `json:"manifest"`
	Signature []byte `json:"signature"`
	Archive   []byte `json:"archive"`
}

// SignBundle signs the manifest and assembles the bundle.
func SignBundle(s *signing.Signer, m *Manifest, archive []byte) (*Bundle, error) {
	raw, err := SigningManifest(m)
	if err != nil {
		return nil, err
	}
	return &Bundle{KeyID: s.KeyID(), Manifest: raw, Signature: s.Sign(signing.DomainModuleManifest, raw), Archive: archive}, nil
}

// Verified is a bundle whose signature and manifest have been checked.
type Verified struct {
	Manifest     *Manifest
	ManifestRaw  []byte
	ManifestHash []byte
	KeyID        string
	Signature    []byte
}

// VerifyManifest checks the manifest signature with the trusted module keys
// and parses it.
func VerifyManifest(keys *signing.Keyring, keyID string, raw, sig []byte) (*Verified, error) {
	if err := keys.Verify(signing.DomainModuleManifest, keyID, raw, sig); err != nil {
		return nil, fmt.Errorf("module manifest: %w", err)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	return &Verified{Manifest: m, ManifestRaw: raw, ManifestHash: ManifestHash(raw), KeyID: keyID, Signature: sig}, nil
}

// Verify checks a whole bundle: signature, manifest and archive hash.
func (b *Bundle) Verify(keys *signing.Keyring) (*Verified, error) {
	v, err := VerifyManifest(keys, b.KeyID, b.Manifest, b.Signature)
	if err != nil {
		return nil, err
	}
	if len(b.Archive) > MaxArchiveSize {
		return nil, errors.New("archive too large")
	}
	if err := checkArchiveHash(v.Manifest, b.Archive); err != nil {
		return nil, err
	}
	return v, nil
}

func checkArchiveHash(m *Manifest, archive []byte) error {
	if hexSHA256(archive) != m.ArchiveSHA256 {
		return errors.New("archive hash does not match the manifest")
	}
	return nil
}
