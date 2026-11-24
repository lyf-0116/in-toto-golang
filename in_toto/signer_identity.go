package in_toto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ErrPublicKeyFingerprint is returned when a stable public key fingerprint
// cannot be derived from a Key.
var ErrPublicKeyFingerprint = errors.New("could not derive public key fingerprint")

// cryptoPublicKey extracts the canonical Go public key from an in-toto Key.
// Ed25519 public values are stored as raw hexadecimal bytes, while RSA and
// ECDSA values are PEM-encoded SubjectPublicKeyInfo. Certificate-backed keys
// fall back to the certificate's public key.
func (k Key) cryptoPublicKey() (crypto.PublicKey, error) {
	if publicValue := strings.TrimSpace(k.KeyVal.Public); publicValue != "" {
		if _, parsedKey, err := decodeAndParse([]byte(publicValue)); err == nil {
			return publicKeyFromParsed(parsedKey)
		}

		if block, _ := pem.Decode([]byte(publicValue)); block != nil {
			if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
				return key, nil
			}
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return &key.PublicKey, nil
			}
		}

		rawKey, err := hex.DecodeString(publicValue)
		if err != nil {
			return nil, fmt.Errorf("%w: decode public key: %v", ErrPublicKeyFingerprint, err)
		}

		if key, err := x509.ParsePKIXPublicKey(rawKey); err == nil {
			return publicKeyFromParsed(key)
		}

		if len(rawKey) == ed25519.PublicKeySize {
			return ed25519.PublicKey(rawKey), nil
		}

		return nil, fmt.Errorf("%w: unrecognized raw public key", ErrPublicKeyFingerprint)
	}

	if certificateValue := strings.TrimSpace(k.KeyVal.Certificate); certificateValue != "" {
		if _, parsedCertificate, err := decodeAndParse([]byte(certificateValue)); err == nil {
			return publicKeyFromParsed(parsedCertificate)
		}
	}

	return nil, fmt.Errorf("%w: empty public key", ErrPublicKeyFingerprint)
}

func publicKeyFromParsed(parsedKey any) (crypto.PublicKey, error) {
	switch key := parsedKey.(type) {
	case *rsa.PublicKey:
		return key, nil
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PublicKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PublicKey:
		return key, nil
	case ed25519.PrivateKey:
		publicKey, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: invalid Ed25519 private key", ErrPublicKeyFingerprint)
		}
		return publicKey, nil
	case *x509.Certificate:
		return publicKeyFromParsed(key.PublicKey)
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrPublicKeyFingerprint, parsedKey)
	}
}

// CryptoPublicKeyFingerprint returns the canonical fingerprint of a Go
// crypto.PublicKey implementation supported by in-toto.
func CryptoPublicKeyFingerprint(publicKey crypto.PublicKey) (string, error) {
	publicKey, err := publicKeyFromParsed(publicKey)
	if err != nil {
		return "", err
	}

	derKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("%w: marshal public key: %v", ErrPublicKeyFingerprint, err)
	}

	fingerprint := sha256.Sum256(derKey)
	return hex.EncodeToString(fingerprint[:]), nil
}

func publicKeyFingerprint(key Key) (string, error) {
	publicKey, err := key.cryptoPublicKey()
	if err != nil {
		return "", err
	}
	return CryptoPublicKeyFingerprint(publicKey)
}

// PublicKeyFingerprint returns a stable fingerprint of the public key material.
// The fingerprint is independent of the asserted KeyID, so the same key
// registered under two identifiers is still recognized as one signer.
func PublicKeyFingerprint(key Key) (string, error) {
	return publicKeyFingerprint(key)
}

// Fingerprint returns the public key fingerprint. It retains the error return
// so callers can distinguish an unsupported key from an empty identifier.
func (k Key) Fingerprint() (string, error) {
	return PublicKeyFingerprint(k)
}

// PublicKeyFingerprint is the method form of PublicKeyFingerprint.
func (k Key) PublicKeyFingerprint() (string, error) {
	return PublicKeyFingerprint(k)
}

// signerIdentity returns the asserted key identifier when present and derives a
// public key fingerprint otherwise.
func signerIdentity(key Key) (string, error) {
	if key.KeyID != "" {
		return key.KeyID, nil
	}
	return PublicKeyFingerprint(key)
}
