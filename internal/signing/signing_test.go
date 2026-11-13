package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func setup(t *testing.T) (*Signer, *Keyring) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	k := NewKeyring()
	if _, err := k.Add(pub, DomainJob); err != nil {
		t.Fatal(err)
	}
	return s, k
}

func TestSignVerify(t *testing.T) {
	s, k := setup(t)
	payload := []byte("hello")
	sig := s.Sign(DomainJob, payload)
	if err := k.Verify(DomainJob, s.KeyID(), payload, sig); err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(DomainJob, s.KeyID(), []byte("hellO"), sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered payload: %v", err)
	}
	if err := k.Verify(DomainJob, "unknown", payload, sig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestDomainSeparation(t *testing.T) {
	s, k := setup(t)
	payload := []byte("manifest")
	// A key trusted only for jobs must not validate manifests, and a
	// signature made for manifests must not validate as a job.
	sig := s.Sign(DomainModuleManifest, payload)
	if err := k.Verify(DomainModuleManifest, s.KeyID(), payload, sig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("key used outside its domain: %v", err)
	}
	if err := k.Verify(DomainJob, s.KeyID(), payload, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("cross-domain signature accepted: %v", err)
	}
}

func TestKeyEncodingRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p, err := ParsePublicKey(EncodePublicKey(pub))
	if err != nil || !p.Equal(pub) {
		t.Fatalf("public key round trip: %v", err)
	}
	k, err := ParsePrivateKey(EncodePrivateKey(priv))
	if err != nil || !k.Equal(priv) {
		t.Fatalf("private key round trip: %v", err)
	}
	if _, err := ParsePublicKey("ed25519:AAAA"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestSelfVerify(t *testing.T) {
	s, _ := setup(t)
	payload := []byte("assignment")
	sig := s.Sign(DomainAssignment, payload)
	if err := s.Verify(DomainAssignment, s.KeyID(), payload, sig); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(DomainAssignment, s.KeyID(), []byte("assignmenT"), sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered payload: %v", err)
	}
	if err := s.Verify(DomainJob, s.KeyID(), payload, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("cross-domain signature accepted: %v", err)
	}
	if err := s.Verify(DomainAssignment, "unknown", payload, sig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	other, _ := NewSigner(ed25519mustGenerate(t))
	if err := other.Verify(DomainAssignment, s.KeyID(), payload, sig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("another signer accepted a foreign key id: %v", err)
	}
}

func ed25519mustGenerate(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
