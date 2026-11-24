package in_toto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func mustGenerateThresholdDedupTestKey(t *testing.T, keyType string) Key {
	t.Helper()

	var privateKey crypto.PrivateKey
	var err error

	switch keyType {
	case rsaKeyType:
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case ecdsaKeyType:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ed25519KeyType:
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unsupported test key type %q", keyType)
	}
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivateKey,
		Bytes: der,
	})

	var key Key
	require.NoError(t, key.LoadKeyReaderDefaults(bytes.NewReader(pemBytes)))
	return key
}

func TestVerifyLinkSignatureThresholdDeduplicatesCertificateKey(t *testing.T) {
	rootCert, _, rootKey, err := createSelfSignedCA(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "Dedup Root CA"},
		MaxPathLen:            1,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, x509.Ed25519, time.Hour)
	require.NoError(t, err)

	intermediateCert, _, intermediateKey, err := createCA(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "Dedup Intermediate CA"},
		MaxPathLen:            0,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, rootCert, rootKey, x509.Ed25519, time.Hour)
	require.NoError(t, err)

	_, leafCertPEM, leafPrivateKey, err := createEndEntityCert(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "dedup-functionary", Organization: []string{"example"}},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, intermediateCert, intermediateKey, x509.Ed25519, time.Hour)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(leafPrivateKey)
	require.NoError(t, err)
	var certKey Key
	require.NoError(t, certKey.LoadKeyReaderDefaults(bytes.NewReader(pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivateKey,
		Bytes: der,
	}))))
	certKey.KeyVal.Certificate = string(leafCertPEM)

	metadata := &Metablock{Signed: Link{Type: "link", Name: "foo"}}
	require.NoError(t, metadata.Sign(certKey))

	layout := Layout{
		Steps: []Step{{
			Type:      "step",
			Threshold: 2,
			SupplyChainItem: SupplyChainItem{
				Name: "foo",
			},
			CertificateConstraints: []CertificateConstraint{{
				CommonName:    "*",
				DNSNames:      []string{"*"},
				Emails:        []string{"*"},
				Organizations: []string{"*"},
				URIs:          []string{"*"},
				Roots:         []string{"*"},
			}},
		}},
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediatePool := x509.NewCertPool()
	intermediatePool.AddCert(intermediateCert)
	stepsMetadata := map[string]map[string]Metadata{
		"foo": {
			certKey.KeyID: metadata,
			"wrapper-2":   metadata,
		},
	}

	result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata, rootPool, intermediatePool)
	require.Error(t, err)
	require.Nil(t, result)

	layout.Steps[0].Threshold = 1
	result, err = VerifyLinkSignatureThesholds(layout, stepsMetadata, rootPool, intermediatePool)
	require.NoError(t, err)
	require.Len(t, result["foo"], 1)
}

func TestPublicKeyFingerprintSupportsAllKeyTypes(t *testing.T) {
	for _, keyType := range []string{rsaKeyType, ecdsaKeyType, ed25519KeyType} {
		t.Run(keyType, func(t *testing.T) {
			key := mustGenerateThresholdDedupTestKey(t, keyType)

			fingerprint, err := PublicKeyFingerprint(key)
			require.NoError(t, err)
			require.Len(t, fingerprint, hex.EncodedLen(32))

			methodFingerprint, err := key.Fingerprint()
			require.NoError(t, err)
			require.Equal(t, fingerprint, methodFingerprint)

			relabeledKey := key
			relabeledKey.KeyID = "different-key-identifier"
			relabeledFingerprint, err := PublicKeyFingerprint(relabeledKey)
			require.NoError(t, err)
			require.Equal(t, fingerprint, relabeledFingerprint)

			keyless := key
			keyless.KeyID = ""
			keylessFingerprint, err := signerIdentity(keyless)
			require.NoError(t, err)
			require.Equal(t, fingerprint, keylessFingerprint)

			otherKey := mustGenerateThresholdDedupTestKey(t, keyType)
			otherFingerprint, err := PublicKeyFingerprint(otherKey)
			require.NoError(t, err)
			require.NotEqual(t, fingerprint, otherFingerprint)
		})
	}
}

func TestVerifyLinkSignatureThresholdDeduplicatesPublicKey(t *testing.T) {
	key := mustGenerateThresholdDedupTestKey(t, ed25519KeyType)
	duplicateID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	duplicateKey := key
	duplicateKey.KeyID = duplicateID

	newSignedLink := func(t *testing.T, signingKey Key) *Metablock {
		t.Helper()
		metadata := &Metablock{Signed: Link{Type: "link", Name: "foo"}}
		require.NoError(t, metadata.Sign(signingKey))
		return metadata
	}

	layout := Layout{
		Steps: []Step{{
			Type: "step",
			SupplyChainItem: SupplyChainItem{
				Name: "foo",
			},
			Threshold: 2,
			PubKeys:   []string{key.KeyID, duplicateID},
		}},
		Keys: map[string]Key{
			key.KeyID:   key,
			duplicateID: duplicateKey,
		},
	}

	t.Run("same key under two identifiers is one signer", func(t *testing.T) {
		stepsMetadata := map[string]map[string]Metadata{
			"foo": {
				key.KeyID:   newSignedLink(t, key),
				duplicateID: newSignedLink(t, duplicateKey),
			},
		}

		result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata,
			x509.NewCertPool(), x509.NewCertPool())
		require.Error(t, err)
		require.Nil(t, result)
	})

	t.Run("same signature in two wrappers is one signer", func(t *testing.T) {
		metadata := newSignedLink(t, key)
		stepsMetadata := map[string]map[string]Metadata{
			"foo": {
				key.KeyID:   metadata,
				duplicateID: metadata,
			},
		}

		result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata,
			x509.NewCertPool(), x509.NewCertPool())
		require.Error(t, err)
		require.Nil(t, result)
	})

	t.Run("same signature under arbitrary wrapper names", func(t *testing.T) {
		singleKeyLayout := layout
		singleKeyLayout.Steps = []Step{layout.Steps[0]}
		singleKeyLayout.Steps[0].PubKeys = []string{key.KeyID}
		singleKeyLayout.Keys = map[string]Key{key.KeyID: key}
		metadata := newSignedLink(t, key)
		stepsMetadata := map[string]map[string]Metadata{
			"foo": {
				"wrapper-1": metadata,
				"wrapper-2": metadata,
			},
		}

		result, err := VerifyLinkSignatureThesholds(singleKeyLayout, stepsMetadata,
			x509.NewCertPool(), x509.NewCertPool())
		require.Error(t, err)
		require.Nil(t, result)
	})

	t.Run("threshold one accepts deduplicated signer", func(t *testing.T) {
		thresholdOne := layout
		thresholdOne.Steps = []Step{layout.Steps[0]}
		thresholdOne.Steps[0].Threshold = 1

		stepsMetadata := map[string]map[string]Metadata{
			"foo": {
				key.KeyID:   newSignedLink(t, key),
				duplicateID: newSignedLink(t, duplicateKey),
			},
		}

		result, err := VerifyLinkSignatureThesholds(thresholdOne, stepsMetadata,
			x509.NewCertPool(), x509.NewCertPool())
		require.NoError(t, err)
		require.Len(t, result["foo"], 1)
	})
}

func TestVerifyLinkSignatureThresholdDeduplicatesMissingKeyID(t *testing.T) {
	for _, keyType := range []string{rsaKeyType, ecdsaKeyType, ed25519KeyType} {
		t.Run(keyType, func(t *testing.T) {
			signingKey := mustGenerateThresholdDedupTestKey(t, keyType)
			signingKey.KeyID = ""

			metadata := &Metablock{Signed: Link{Type: "link", Name: "foo"}}
			require.NoError(t, metadata.Sign(signingKey))

			layout := Layout{
				Steps: []Step{{
					Type: "step",
					SupplyChainItem: SupplyChainItem{
						Name: "foo",
					},
					Threshold: 2,
					PubKeys:   []string{"signer-name-1", "signer-name-2"},
				}},
				Keys: map[string]Key{
					"signer-name-1": signingKey,
					"signer-name-2": signingKey,
				},
			}
			stepsMetadata := map[string]map[string]Metadata{
				"foo": {
					"wrapper-1": metadata,
					"wrapper-2": metadata,
				},
			}

			result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata,
				x509.NewCertPool(), x509.NewCertPool())
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
}

func TestVerifyLinkSignatureThresholdAcceptsDistinctKeylessPublicKeys(t *testing.T) {
	firstKey := mustGenerateThresholdDedupTestKey(t, ed25519KeyType)
	secondKey := mustGenerateThresholdDedupTestKey(t, ed25519KeyType)
	firstKey.KeyID = ""
	secondKey.KeyID = ""

	firstMetadata := &Metablock{Signed: Link{Type: "link", Name: "foo"}}
	secondMetadata := &Metablock{Signed: Link{Type: "link", Name: "foo"}}
	require.NoError(t, firstMetadata.Sign(firstKey))
	require.NoError(t, secondMetadata.Sign(secondKey))

	layout := Layout{
		Steps: []Step{{
			Type: "step",
			SupplyChainItem: SupplyChainItem{
				Name: "foo",
			},
			Threshold: 2,
			PubKeys:   []string{"role-1", "role-2"},
		}},
		Keys: map[string]Key{
			"role-1": firstKey,
			"role-2": secondKey,
		},
	}
	stepsMetadata := map[string]map[string]Metadata{
		"foo": {
			"wrapper-1": firstMetadata,
			"wrapper-2": secondMetadata,
		},
	}

	result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata,
		x509.NewCertPool(), x509.NewCertPool())
	require.NoError(t, err)
	require.Len(t, result["foo"], 2)
}

func TestVerifyLinkSignatureThresholdDeduplicatesDSSEEnvelopes(t *testing.T) {
	key := mustGenerateThresholdDedupTestKey(t, ed25519KeyType)
	duplicateID := "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"
	duplicateKey := key
	duplicateKey.KeyID = duplicateID

	newEnvelope := func(t *testing.T, signingKey Key) Metadata {
		t.Helper()
		envelope := &Envelope{}
		require.NoError(t, envelope.SetPayload(Link{Type: "link", Name: "foo"}))
		require.NoError(t, envelope.Sign(signingKey))
		return envelope
	}

	layout := Layout{
		Steps: []Step{{
			Type: "step",
			SupplyChainItem: SupplyChainItem{
				Name: "foo",
			},
			Threshold: 2,
			PubKeys:   []string{key.KeyID, duplicateID},
		}},
		Keys: map[string]Key{
			key.KeyID:   key,
			duplicateID: duplicateKey,
		},
	}
	stepsMetadata := map[string]map[string]Metadata{
		"foo": {
			"wrapper-1": newEnvelope(t, key),
			"wrapper-2": newEnvelope(t, duplicateKey),
		},
	}

	result, err := VerifyLinkSignatureThesholds(layout, stepsMetadata,
		x509.NewCertPool(), x509.NewCertPool())
	require.Error(t, err)
	require.Nil(t, result)
}
