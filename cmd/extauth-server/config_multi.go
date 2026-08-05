package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	src "github.com/BlackDark/test-oidc-traefik-plugin/src"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"gopkg.in/yaml.v3"
)

// multiConfig is the extauth-server YAML root. Breaking change vs single-client JSON.
type multiConfig struct {
	Clients []clientEntry
}

type clientEntry struct {
	ID     string
	Hosts  []string
	Config *config.Config
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func parseMultiConfigFile(path string) (*multiConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // CONFIG_FILE is operator-supplied deployment config
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return parseMultiConfig(data)
}

func parseMultiConfig(data []byte) (*multiConfig, error) {
	var raw struct {
		Clients []yaml.Node `yaml:"clients"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}
	if len(raw.Clients) == 0 {
		return nil, fmt.Errorf("clients: must contain at least one client")
	}

	out := &multiConfig{Clients: make([]clientEntry, 0, len(raw.Clients))}
	for i, node := range raw.Clients {
		var meta struct {
			ID    string   `yaml:"id"`
			Hosts []string `yaml:"hosts"`
		}
		if err := node.Decode(&meta); err != nil {
			return nil, fmt.Errorf("clients[%d]: %w", i, err)
		}
		if meta.ID == "" {
			return nil, fmt.Errorf("clients[%d]: id is required", i)
		}
		if len(meta.Hosts) == 0 {
			return nil, fmt.Errorf("clients[%d] (%s): hosts must be non-empty", i, meta.ID)
		}

		cfg := src.CreateConfig()
		if err := node.Decode(cfg); err != nil {
			return nil, fmt.Errorf("clients[%d] (%s): %w", i, meta.ID, err)
		}
		out.Clients = append(out.Clients, clientEntry{
			ID:     meta.ID,
			Hosts:  meta.Hosts,
			Config: cfg,
		})
	}

	if err := validateMultiConfig(out); err != nil {
		return nil, err
	}
	return out, nil
}

func validateMultiConfig(cfg *multiConfig) error {
	ids := make(map[string]string, len(cfg.Clients))
	hosts := make(map[string]string) // host -> client id
	prefixes := make(map[string]string)
	secrets := make(map[string]string)

	for _, c := range cfg.Clients {
		if prev, ok := ids[c.ID]; ok {
			return fmt.Errorf("duplicate id %q (also used by %s)", c.ID, prev)
		}
		ids[c.ID] = c.ID

		prefix := c.Config.CookieNamePrefix
		if prev, ok := prefixes[prefix]; ok {
			return fmt.Errorf("duplicate cookieNamePrefix %q for clients %q and %q", prefix, prev, c.ID)
		}
		prefixes[prefix] = c.ID

		if c.Config.Secret != "" && c.Config.Secret != config.DefaultSecret {
			if prev, ok := secrets[c.Config.Secret]; ok {
				return fmt.Errorf("duplicate secret for clients %q and %q", prev, c.ID)
			}
			secrets[c.Config.Secret] = c.ID
		}

		seen := make(map[string]struct{}, len(c.Hosts))
		for _, h := range c.Hosts {
			n := normalizeHost(h)
			if n == "" {
				return fmt.Errorf("client %q: empty host", c.ID)
			}
			if strings.HasPrefix(n, "*.") && len(n) < 4 {
				return fmt.Errorf("client %q: invalid wildcard host %q", c.ID, n)
			}
			if _, ok := seen[n]; ok {
				continue // same client listing aliases that normalize equal
			}
			seen[n] = struct{}{}
			if prev, ok := hosts[n]; ok {
				return fmt.Errorf("duplicate host %q for clients %q and %q", n, prev, c.ID)
			}
			hosts[n] = c.ID
		}
	}
	return nil
}
