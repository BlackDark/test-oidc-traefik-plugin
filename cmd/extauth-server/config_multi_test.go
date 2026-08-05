package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"grafana.example.com", "grafana.example.com"},
		{"Grafana.Example.COM", "grafana.example.com"},
		{"grafana.example.com:443", "grafana.example.com"},
		{"GRAFANA.example.com:8443", "grafana.example.com"},
		{"  grafana.example.com  ", "grafana.example.com"},
	}
	for _, tt := range tests {
		if got := normalizeHost(tt.in); got != tt.want {
			t.Fatalf("normalizeHost(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseMultiConfig_Valid(t *testing.T) {
	yaml := `
clients:
  - id: grafana
    hosts:
      - grafana.example.com
      - Grafana.Example.COM
    secret: "0123456789abcdef0123456789abcdef"
    provider:
      url: https://idp.example.com
      clientId: grafana
      clientSecret: secret-a
    cookieNamePrefix: grafana
  - id: argo
    hosts:
      - argo.example.com
    secret: "fedcba9876543210fedcba9876543210"
    provider:
      url: https://idp.example.com
      clientId: argo
      clientSecret: secret-b
    cookieNamePrefix: argo
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := parseMultiConfigFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Clients) != 2 {
		t.Fatalf("clients=%d want 2", len(cfg.Clients))
	}
	if cfg.Clients[0].ID != "grafana" {
		t.Fatalf("id=%q", cfg.Clients[0].ID)
	}
	if cfg.Clients[0].Config.Provider.ClientId != "grafana" {
		t.Fatalf("clientId=%q", cfg.Clients[0].Config.Provider.ClientId)
	}
	if cfg.Clients[1].Config.CookieNamePrefix != "argo" {
		t.Fatalf("cookieNamePrefix=%q", cfg.Clients[1].Config.CookieNamePrefix)
	}
}

func TestParseMultiConfig_RejectsEmptyClients(t *testing.T) {
	path := writeYAML(t, "clients: []\n")
	if _, err := parseMultiConfigFile(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseMultiConfig_RejectsDuplicateHost(t *testing.T) {
	yaml := `
clients:
  - id: a
    hosts: [app.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: a
  - id: b
    hosts: [APP.example.com:443]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: b}
    cookieNamePrefix: b
`
	path := writeYAML(t, yaml)
	_, err := parseMultiConfigFile(path)
	if err == nil {
		t.Fatal("expected duplicate host error")
	}
	if !strings.Contains(err.Error(), "duplicate host") {
		t.Fatalf("err=%v", err)
	}
}

func TestParseMultiConfig_RejectsDuplicateID(t *testing.T) {
	yaml := `
clients:
  - id: same
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: a
  - id: same
    hosts: [b.example.com]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: b}
    cookieNamePrefix: b
`
	path := writeYAML(t, yaml)
	_, err := parseMultiConfigFile(path)
	if err == nil {
		t.Fatal("expected duplicate id error")
	}
}

func TestParseMultiConfig_RejectsDuplicateCookiePrefix(t *testing.T) {
	yaml := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: a}
    cookieNamePrefix: shared
  - id: b
    hosts: [b.example.com]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: b}
    cookieNamePrefix: shared
`
	path := writeYAML(t, yaml)
	_, err := parseMultiConfigFile(path)
	if err == nil {
		t.Fatal("expected duplicate cookieNamePrefix error")
	}
}

func TestParseMultiConfig_FileExpand(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "client-secret")
	if err := os.WriteFile(secretPath, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider:
      url: https://idp.example.com
      clientId: a
      clientSecret: ${file:` + secretPath + `}
    cookieNamePrefix: a
`
	path := writeYAML(t, yaml)
	cfg, err := parseMultiConfigFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Expansion happens in src.New, not parse — raw value should still be the ${file:...} form
	if !strings.Contains(cfg.Clients[0].Config.Provider.ClientSecret, "file:") {
		t.Fatalf("expected unexpanded file ref, got %q", cfg.Clients[0].Config.Provider.ClientSecret)
	}
}

func writeYAML(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
