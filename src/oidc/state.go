package oidc

import (
	"encoding/base64"
	"encoding/json"

	"github.com/sevensolutions/traefik-oidc-auth/src/utils"
)

type OidcState struct {
	Action      string `json:"action"`
	RedirectUrl string `json:"redirect_url"`
	// CodeVerifierEnc is the AES-GCM encrypted PKCE code_verifier (utils.Encrypt output).
	// Nested inside JSON then sealed by SealState — do not put Encrypt output bare in a query string.
	// Carried in state so parallel login redirects cannot overwrite each other via a shared cookie.
	CodeVerifierEnc string `json:"cve,omitempty"`
	// Csrf binds this authorize flow to a LoginCsrf cookie (ADR 0003).
	Csrf string `json:"csrf,omitempty"`
	// Nonce is the OIDC nonce for ID token binding (ADR 0004).
	Nonce string `json:"nonce,omitempty"`
	// IsChallenge is set when login was triggered by UnauthorizedBehavior Challenge (authorization re-check).
	IsChallenge bool `json:"is_challenge,omitempty"`
}

// SealState encrypts the full OidcState with Secret and returns a RawURL-safe opaque state string (ADR 0002).
func SealState(state *OidcState, secret string) (string, error) {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return "", err
	}

	encrypted, err := utils.Encrypt(string(stateBytes), secret)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString([]byte(encrypted)), nil
}

// UnsealState decrypts an opaque state string produced by SealState.
func UnsealState(sealed string, secret string) (*OidcState, error) {
	encBytes, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return nil, err
	}

	plain, err := utils.Decrypt(string(encBytes), secret)
	if err != nil {
		return nil, err
	}

	var state OidcState
	if err := json.Unmarshal([]byte(plain), &state); err != nil {
		return nil, err
	}

	return &state, nil
}
