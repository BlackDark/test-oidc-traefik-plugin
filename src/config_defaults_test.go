package src

import (
	"context"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
)

func TestNew_RefusesDefaultSecret(t *testing.T) {
	cfg := CreateConfig()
	cfg.Provider.Url = "https://idp.example.com"
	cfg.Provider.ClientId = "client"
	cfg.Secret = config.DefaultSecret

	_, err := New(context.Background(), nil, cfg, "test")
	if err == nil {
		t.Fatal("expected error for default secret")
	}
	if err.Error() != "default secret is not allowed" {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateConfig_SecureDefaults(t *testing.T) {
	cfg := CreateConfig()
	if !cfg.Provider.UsePkceBool {
		t.Fatal("UsePkce should default true")
	}
	if !cfg.Provider.ValidateNonceBool {
		t.Fatal("ValidateNonce should default true")
	}
	if cfg.SessionCookie.SameSite != "lax" {
		t.Fatalf("SameSite=%q want lax", cfg.SessionCookie.SameSite)
	}
	if cfg.Provider.TokenClockSkewSeconds != 60 {
		t.Fatalf("TokenClockSkewSeconds=%d", cfg.Provider.TokenClockSkewSeconds)
	}
}
