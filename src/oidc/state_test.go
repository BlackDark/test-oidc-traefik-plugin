package oidc

import "testing"

func TestEncodeDecodeState_WithCodeVerifierEnc(t *testing.T) {
	in := &OidcState{
		Action:          "Login",
		RedirectUrl:     "https://app.example.com/path",
		CodeVerifierEnc: "encrypted-verifier-ciphertext",
	}

	encoded, err := EncodeState(in)
	if err != nil {
		t.Fatalf("EncodeState: %v", err)
	}
	if encoded == "" {
		t.Fatal("expected non-empty encoded state")
	}

	out, err := DecodeState(encoded)
	if err != nil {
		t.Fatalf("DecodeState: %v", err)
	}
	if out.Action != in.Action {
		t.Fatalf("Action: got %q want %q", out.Action, in.Action)
	}
	if out.RedirectUrl != in.RedirectUrl {
		t.Fatalf("RedirectUrl: got %q want %q", out.RedirectUrl, in.RedirectUrl)
	}
	if out.CodeVerifierEnc != in.CodeVerifierEnc {
		t.Fatalf("CodeVerifierEnc: got %q want %q", out.CodeVerifierEnc, in.CodeVerifierEnc)
	}
}

func TestEncodeDecodeState_OmitsEmptyCodeVerifierEnc(t *testing.T) {
	in := &OidcState{Action: "Login", RedirectUrl: "https://app.example.com/"}
	encoded, err := EncodeState(in)
	if err != nil {
		t.Fatalf("EncodeState: %v", err)
	}
	out, err := DecodeState(encoded)
	if err != nil {
		t.Fatalf("DecodeState: %v", err)
	}
	if out.CodeVerifierEnc != "" {
		t.Fatalf("expected empty CodeVerifierEnc, got %q", out.CodeVerifierEnc)
	}
}
