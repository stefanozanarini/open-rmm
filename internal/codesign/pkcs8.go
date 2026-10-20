package codesign

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
)

// Encrypted keys use PKCS#8 with PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC),
// the format of "openssl pkcs8 -topk8 -v2 aes-256-cbc": OpenSSL and
// osslsigncode read it with the passphrase, so the key is never written in
// clear.

const (
	pbkdf2Iterations = 600000
	// MinPassphrase is the shortest passphrase accepted.
	MinPassphrase = 16
)

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	// ErrPassphrase is returned when a key cannot be decrypted.
	ErrPassphrase = errors.New("wrong passphrase or damaged key")
)

type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier
}

// EncryptKeyPEM encrypts a private key with a passphrase.
func EncryptKeyPEM(key crypto.Signer, passphrase string) ([]byte, error) {
	if len(passphrase) < MinPassphrase {
		return nil, errors.New("the passphrase must have at least 16 characters")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	k, err := pbkdf2.Key(sha256.New, passphrase, salt, pbkdf2Iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(der)%aes.BlockSize
	plain := append(der, bytes.Repeat([]byte{byte(pad)}, pad)...)
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, plain)
	kdf, err := asn1.Marshal(pbkdf2Params{Salt: salt, Iterations: pbkdf2Iterations,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue}})
	if err != nil {
		return nil, err
	}
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	params, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		EncryptionScheme:  pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return nil, err
	}
	out, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}}, Data: enc})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: out}), nil
}

// DecryptKeyPEM decrypts a key written by EncryptKeyPEM (or by OpenSSL with
// the same scheme).
func DecryptKeyPEM(data []byte, passphrase string) (crypto.Signer, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, errors.New("no encrypted PKCS#8 key found")
	}
	var info encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(b.Bytes, &info); err != nil || !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("unsupported key encryption")
	}
	var params pbes2Params
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, errors.New("unsupported key encryption")
	}
	var kdf pbkdf2Params
	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) || !params.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		return nil, errors.New("unsupported key encryption")
	}
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil ||
		!kdf.PRF.Algorithm.Equal(oidHMACSHA256) || kdf.Iterations < 1000 || kdf.Iterations > 10000000 {
		return nil, errors.New("unsupported key derivation")
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("unsupported key encryption")
	}
	k, err := pbkdf2.Key(sha256.New, passphrase, kdf.Salt, kdf.Iterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	if len(info.Data) == 0 || len(info.Data)%aes.BlockSize != 0 {
		return nil, ErrPassphrase
	}
	plain := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, info.Data)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > aes.BlockSize || !bytes.Equal(plain[len(plain)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, ErrPassphrase
	}
	key, err := x509.ParsePKCS8PrivateKey(plain[:len(plain)-pad])
	if err != nil {
		return nil, ErrPassphrase
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a signer")
	}
	return s, nil
}
