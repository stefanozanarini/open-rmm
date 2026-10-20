package builder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openrmmv1 "github.com/stefanozanarini/open-rmm/gen/openrmm/v1"
	"github.com/stefanozanarini/open-rmm/internal/codesign"
	"github.com/stefanozanarini/open-rmm/internal/modules"
	"github.com/stefanozanarini/open-rmm/internal/release"
	"github.com/stefanozanarini/open-rmm/internal/signing"
)

// The module and agent release keys (ed25519) live next to the Authenticode
// key, encrypted with the same passphrase. Each signs only its own domain,
// and only a manifest that parses as one: the builder never signs arbitrary
// bytes.
const (
	fileModuleKey  = "module-release.key"
	fileReleaseKey = "agent-release.key"
)

// Kinds of manifest SignManifest accepts.
const (
	KindModule  = "module"
	KindRelease = "release"
)

// checkPassphrase verifies that pass opens the keys already held, so that
// one passphrase protects them all. With no key yet, any passphrase of the
// minimum length is accepted.
func (s *Service) checkPassphrase(pass string) error {
	if len(pass) < codesign.MinPassphrase {
		return invalid(errors.New("the passphrase must have at least 16 characters"))
	}
	for _, f := range []string{fileModuleKey, fileKey, fileCAKey, fileRequestKey} {
		raw, err := os.ReadFile(s.path(f))
		if err != nil {
			continue
		}
		if _, err := codesign.DecryptKeyPEM(raw, pass); err != nil {
			return status.Error(codes.PermissionDenied, "wrong passphrase: use the passphrase of the console's signing keys")
		}
		return nil
	}
	return nil
}

func (s *Service) publicKey(name string) string {
	raw, err := os.ReadFile(s.path(name + ".pub"))
	if err != nil {
		return ""
	}
	return string(raw)
}

// CreateReleaseKeys creates the module and agent release keys. They are
// created once: replacing them would orphan every agent that trusts them.
func (s *Service) CreateReleaseKeys(_ context.Context, req *openrmmv1.CreateReleaseKeysRequest) (*openrmmv1.BuilderStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exists(fileModuleKey) || s.exists(fileReleaseKey) {
		return nil, status.Error(codes.AlreadyExists, "the release keys already exist")
	}
	if err := s.checkPassphrase(req.GetPassphrase()); err != nil {
		return nil, err
	}
	for _, name := range []string{fileModuleKey, fileReleaseKey} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		enc, err := codesign.EncryptKeyPEM(priv, req.GetPassphrase())
		if err != nil {
			return nil, invalid(err)
		}
		if err := s.write(name+".pub", []byte(signing.EncodePublicKey(pub))); err != nil {
			return nil, err
		}
		if err := s.write(name, enc); err != nil {
			return nil, err
		}
		s.Log.Info("release key created", "file", name, "key_id", signing.KeyID(pub))
	}
	return s.status()
}

// SignManifest signs a module or agent release manifest with its key.
func (s *Service) SignManifest(_ context.Context, req *openrmmv1.SignManifestRequest) (*openrmmv1.SignManifestResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw := req.GetManifest()
	var file string
	var domain signing.Domain
	var what []any
	switch req.GetKind() {
	case KindModule:
		m, err := modules.ParseManifest(raw)
		if err != nil {
			return nil, invalid(err)
		}
		file, domain, what = fileModuleKey, signing.DomainModuleManifest, []any{"module", m.ID, "version", m.Version}
	case KindRelease:
		m, err := release.ParseManifest(raw)
		if err != nil {
			return nil, invalid(err)
		}
		file, domain, what = fileReleaseKey, signing.DomainAgentRelease, []any{"release", m.Version, "platform", m.Platform}
	default:
		return nil, invalid(errors.New("unknown manifest kind"))
	}
	enc, err := os.ReadFile(s.path(file))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "the release keys have not been created")
	}
	key, err := codesign.DecryptKeyPEM(enc, req.GetPassphrase())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("release key is not ed25519")
	}
	signer, err := signing.NewSigner(priv)
	if err != nil {
		return nil, err
	}
	s.Log.Info("manifest signed", append(what, "key_id", signer.KeyID())...)
	return &openrmmv1.SignManifestResponse{KeyId: signer.KeyID(), Signature: signer.Sign(domain, raw)}, nil
}
