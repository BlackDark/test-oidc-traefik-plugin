package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
)

func TestBuildHostMap_UsesFactoryPerClient(t *testing.T) {
	yaml := `
clients:
  - id: a
    hosts: [a.example.com, A.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
  - id: b
    hosts: [b.example.com]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: client-b}
    cookieNamePrefix: b
`
	path := writeYAML(t, yaml)
	cfg, err := parseMultiConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]string{}
	factory := func(_ context.Context, _ http.Handler, c *config.Config, name string) (http.Handler, error) {
		id := c.Provider.ClientId
		seen[id] = name
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Client", id)
			w.WriteHeader(http.StatusOK)
		}), nil
	}

	allow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	m, err := buildHostMap(context.Background(), cfg, allow, factory)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("hosts=%d want 2", len(m))
	}
	if seen["client-a"] == "" || seen["client-b"] == "" {
		t.Fatalf("seen=%v", seen)
	}
}

func TestReloadKeepsOldOnBadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	good := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}

	factory := stubFactory()
	allow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	r := newHostRouter()

	if err := reloadFromFile(context.Background(), r, path, allow, factory); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	if err := os.WriteFile(path, []byte(`clients: []`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadFromFile(context.Background(), r, path, allow, factory); err == nil {
		t.Fatal("expected reload error")
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://a.example.com/", nil)
	req.Host = "a.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 from old map", rw.Code)
	}
}

func TestReloadSucceedsOnGoodUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	v1 := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
`
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}

	factory := stubFactory()
	allow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	r := newHostRouter()
	if err := reloadFromFile(context.Background(), r, path, allow, factory); err != nil {
		t.Fatal(err)
	}

	v2 := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: "0123456789abcdef0123456789abcdef"
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
  - id: b
    hosts: [b.example.com]
    secret: "fedcba9876543210fedcba9876543210"
    provider: {url: https://idp.example.com, clientId: client-b}
    cookieNamePrefix: b
`
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadFromFile(context.Background(), r, path, allow, factory); err != nil {
		t.Fatal(err)
	}

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://b.example.com/", nil)
	req.Host = "b.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 for new host", rw.Code)
	}
}

func TestBuildHostMap_RejectsDuplicateSecretAfterExpand(t *testing.T) {
	yaml := `
clients:
  - id: a
    hosts: [a.example.com]
    secret: ${file:WILL_EXPAND_SAME}
    provider: {url: https://idp.example.com, clientId: client-a}
    cookieNamePrefix: a
  - id: b
    hosts: [b.example.com]
    secret: ${file:WILL_EXPAND_SAME_OTHER}
    provider: {url: https://idp.example.com, clientId: client-b}
    cookieNamePrefix: b
`
	path := writeYAML(t, yaml)
	cfg, err := parseMultiConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}

	factory := func(_ context.Context, _ http.Handler, c *config.Config, _ string) (http.Handler, error) {
		c.Secret = "same-expanded-secret-32chars!!!!" // 32 chars
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), nil
	}
	_, err = buildHostMap(context.Background(), cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), factory)
	if err == nil {
		t.Fatal("expected duplicate secret error")
	}
}

func stubFactory() handlerFactory {
	return func(_ context.Context, _ http.Handler, c *config.Config, _ string) (http.Handler, error) {
		id := c.Provider.ClientId
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Client", id)
			w.WriteHeader(http.StatusOK)
		}), nil
	}
}
