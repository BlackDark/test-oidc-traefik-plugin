package oidc

import (
	"encoding/base64"
	"strings"
	"testing"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestSealUnsealState_RoundTrip(t *testing.T) {
	in := &OidcState{
		Action:          "Login",
		RedirectUrl:     "https://app.example.com/path",
		CodeVerifierEnc: "encrypted-verifier-ciphertext",
	}

	sealed, err := SealState(in, testSecret)
	if err != nil {
		t.Fatalf("SealState: %v", err)
	}
	if sealed == "" {
		t.Fatal("expected non-empty sealed state")
	}
	// Must not contain cleartext redirect URL
	if strings.Contains(sealed, "app.example.com") || strings.Contains(string(mustRawURLDecode(t, sealed)), "redirect_url") {
		t.Fatal("sealed state must not expose cleartext JSON fields")
	}

	out, err := UnsealState(sealed, testSecret)
	if err != nil {
		t.Fatalf("UnsealState: %v", err)
	}
	if out.Action != in.Action || out.RedirectUrl != in.RedirectUrl || out.CodeVerifierEnc != in.CodeVerifierEnc {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestUnsealState_TamperedFails(t *testing.T) {
	sealed, err := SealState(&OidcState{Action: "Login", RedirectUrl: "https://evil.example/"}, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	if _, err := UnsealState(tampered, testSecret); err == nil {
		t.Fatal("expected error for tampered state")
	}
}

func TestUnsealState_WrongSecretFails(t *testing.T) {
	sealed, err := SealState(&OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"}, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnsealState(sealed, "ffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestUnsealState_PlainBase64JsonFails(t *testing.T) {
	// Old unsealed format must not be accepted
	legacy := base64.RawURLEncoding.EncodeToString([]byte(`{"action":"Login","redirect_url":"https://evil.example/"}`))
	if _, err := UnsealState(legacy, testSecret); err == nil {
		t.Fatal("legacy unsealed state must be rejected")
	}
}

func mustRawURLDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
