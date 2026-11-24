package in_toto

import (
	"strings"
	"testing"
)

func TestParseExpiresStrict(t *testing.T) {
	valid := "3000-01-02T03:04:05Z"
	parsed, err := ParseExpires(valid)
	if err != nil {
		t.Fatalf("ParseExpires(%q) returned unexpected error: %v", valid, err)
	}
	if parsed.Format(ISO8601DateSchema) != valid {
		t.Fatalf("ParseExpires(%q) round trip = %q", valid,
			parsed.Format(ISO8601DateSchema))
	}

	invalid := []string{
		"",
		"bad date",
		"2030-1-02T03:04:05Z",
		"2030-01-2T03:04:05Z",
		"2030-01-02T3:04:05Z",
		"2030-01-02T03:4:05Z",
		"2030-01-02T03:04:5Z",
		"2030/01/02T03:04:05Z",
		"01/02/2030T03:04:05Z",
		"2030-01-02 03:04:05Z",
		"2030-01-02T03:04:05",
		"2030-01-02T03:04:05z",
		"2030-01-02T03:04:05+00:00",
		"2030-01-02T03:04:05+08:00",
		"2030-01-02T03:04:05.123Z",
		"2030-01-02T03:04:05,123Z",
		"2030-13-02T03:04:05Z",
		"2030-02-30T03:04:05Z",
		"2030-01-02T24:00:00Z",
		" 2030-01-02T03:04:05Z",
		"2030-01-02T03:04:05Z ",
	}

	for _, expires := range invalid {
		t.Run(expires, func(t *testing.T) {
			if _, err := ParseExpires(expires); err == nil {
				t.Fatalf("ParseExpires(%q) accepted non-canonical timestamp",
					expires)
			}

			layout := Layout{Type: "layout", Expires: expires}
			if err := validateLayout(layout); err == nil {
				t.Fatalf("validateLayout accepted non-canonical expiry %q",
					expires)
			}
			if err := VerifyLayoutExpiration(layout); err == nil {
				t.Fatalf("VerifyLayoutExpiration accepted non-canonical expiry %q",
					expires)
			}
		})
	}
}

func TestSignedNonCanonicalExpiryRemainsInvalidForVerification(t *testing.T) {
	var key Key
	if err := key.LoadKey("carol", "ed25519",
		[]string{"sha256", "sha512"}); err != nil {
		t.Fatalf("cannot load signing key: %v", err)
	}

	layout := Layout{
		Type:    "layout",
		Expires: "3000-01-01T00:00:00.123Z",
	}
	layoutEnv := &Metablock{Signed: layout}

	if err := layoutEnv.Sign(key); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if err := layoutEnv.VerifySignature(key); err != nil {
		t.Fatalf("non-canonical expiry changed signed bytes; "+
			"signature verification failed: %v", err)
	}
	if err := VerifyLayoutSignatures(layoutEnv, map[string]Key{
		key.KeyID: key,
	}); err != nil {
		t.Fatalf("VerifyLayoutSignatures returned error: %v", err)
	}

	signedLayout, ok := layoutEnv.GetPayload().(Layout)
	if !ok {
		t.Fatalf("payload type = %T, want Layout", layoutEnv.GetPayload())
	}

	err := VerifyLayoutExpiration(signedLayout)
	if err == nil {
		t.Fatal("VerifyLayoutExpiration accepted fractional-second expiry")
	}
	if !strings.Contains(err.Error(), "does not match required format") {
		t.Fatalf("VerifyLayoutExpiration error = %q, want format error", err)
	}
}
