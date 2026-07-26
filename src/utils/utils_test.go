package utils

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandEnvironmentVariableStringFromEnv(t *testing.T) {
	t.Setenv("TEST_EXPAND_ENV_VAR", "value-from-env")

	result := ExpandEnvironmentVariableString("${TEST_EXPAND_ENV_VAR}")

	if result != "value-from-env" {
		t.Fatalf("expected value-from-env, got %s", result)
	}
}

func TestExpandEnvironmentVariableStringFromFile(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret")

	if err := os.WriteFile(secretFile, []byte("value-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result := ExpandEnvironmentVariableString("${file:" + secretFile + "}")

	if result != "value-from-file" {
		t.Fatalf("expected value-from-file, got %s", result)
	}
}

func TestExpandEnvironmentVariableStringFromMissingFile(t *testing.T) {
	value := "${file:/no/such/file}"

	result := ExpandEnvironmentVariableString(value)

	if result != value {
		t.Fatalf("expected the original value to be returned unchanged, got %s", result)
	}
}

func TestChunkString(t *testing.T) {
	originalText := "abcdefghijklmnopqrstuvwxyz"

	chunks := ChunkString(originalText, 10)

	if len(chunks) != 3 {
		t.Fail()
	}

	value := ""

	var valueSb55 strings.Builder
	for i := 0; i < len(chunks); i++ {
		valueSb55.WriteString(chunks[i])
	}
	value += valueSb55.String()

	if value != originalText {
		t.Fail()
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	secret := "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"
	originalText := "hello"

	encrypted, err := Encrypt(originalText, secret)
	if err != nil {
		t.Fail()
	}

	decrypted, err := Decrypt(encrypted, secret)
	if err != nil {
		t.Fail()
	}

	if decrypted != originalText {
		t.Fail()
	}
}

func TestDecryptEmptyString(t *testing.T) {
	secret := "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

	_, err := Decrypt("", secret)

	// Must return an error
	if err == nil {
		t.Fail()
	}
}

func TestValidateRedirectUri(t *testing.T) {
	validUris := []string{
		"/",
		"https://example.com",
		"https://something.com",
	}

	expectRedirectUriMatch(t, "https://example.com", validUris, false, true)
	expectRedirectUriMatch(t, "https://malicious.com", validUris, false, false)
	expectRedirectUriMatch(t, "https://example.com", validUris, true, true)
	expectRedirectUriMatch(t, "https://EXAMPLE.com", validUris, true, false)
}

func TestValidateRedirectUriWildcardsRequireOptIn(t *testing.T) {
	validUris := []string{
		"*",
		"https://*.example.com",
		"/good/*",
	}

	expectRedirectUriMatch(t, "https://app.example.com", validUris, false, false)
	expectRedirectUriMatch(t, "/good/index.html", validUris, false, false)
	expectRedirectUriMatch(t, "*", validUris, false, true)

	expectRedirectUriMatch(t, "https://app.example.com", validUris, true, true)
	expectRedirectUriMatch(t, "/good/index.html", validUris, true, true)
}

func TestValidateRedirectUriWildcards(t *testing.T) {
	validUris := []string{
		"https://example.com",
		"https://*.something.com",
		"https://*.something.com/good",
		"https://*.something.com/good/*",
		"/app/*",
	}

	expectRedirectUriMatch(t, "https://app.something.com", validUris, true, true)
	expectRedirectUriMatch(t, "https://app.sub.something.com", validUris, true, false)
	expectRedirectUriMatch(t, "https://app.something.com/login", validUris, true, false)
	expectRedirectUriMatch(t, "https://app.something.com/good", validUris, true, true)
	expectRedirectUriMatch(t, "https://app.something.com/good/a/b", validUris, true, true)
	expectRedirectUriMatch(t, "/app", validUris, true, true)
	expectRedirectUriMatch(t, "/app/a/b?next=yes#route", validUris, true, true)
	expectRedirectUriMatch(t, "https://app.something.com/good/a/b", validUris, false, false)
}

func TestValidateRedirectUriWildcardsRejectUnsafeValues(t *testing.T) {
	validUris := []string{"*", "https://*.example.com/*", "/good/*"}

	unsafeUris := []string{
		"//evil.example/good",
		"https://good.example.com@evil.example/good",
		"/good/../secret",
		"/good/%2e%2e/secret",
		"/good/%252e%252e%252fsecret",
		"/good/%25252e%25252e%25252fsecret",
		"/good/%2e%2e%5csecret",
	}

	for _, uri := range unsafeUris {
		expectRedirectUriMatch(t, uri, validUris, true, false)
	}
}

func TestValidateRedirectUriWildcardHostAndPortRules(t *testing.T) {
	expectRedirectUriMatch(t, "https://app.example.com/path", []string{"https://*.example.com/*"}, true, true)
	expectRedirectUriMatch(t, "https://app.sub.example.com/path", []string{"https://*.example.com/*"}, true, false)
	expectRedirectUriMatch(t, "https://example.com.evil/path", []string{"https://example.com*"}, true, false)
	expectRedirectUriMatch(t, "https://example.comevil/path", []string{"https://example.com*/*"}, true, false)
	expectRedirectUriMatch(t, "https://example.com:8443/path", []string{"https://example.com:*/*"}, true, true)
}

func expectRedirectUriMatch(t *testing.T, uri string, validUris []string, wildcardsEnabled bool, shouldMatch bool) {
	t.Helper()

	matchedUri, err := ValidateRedirectUri(uri, validUris, wildcardsEnabled)

	if (shouldMatch && err != nil) || (!shouldMatch && err == nil) {
		t.Fatalf("ValidateRedirectUri(%q, %v, %t) error = %v", uri, validUris, wildcardsEnabled, err)
	}

	if (shouldMatch && matchedUri != uri) || (!shouldMatch && matchedUri != "") {
		t.Fatalf("ValidateRedirectUri(%q, %v, %t) = %q", uri, validUris, wildcardsEnabled, matchedUri)
	}
}

func TestParseAcceptType(t *testing.T) {
	acceptType := ParseAcceptType("text/html")
	if acceptType.Type != "text/html" {
		t.Fail()
	}
	if acceptType.Weight != 1.0 {
		t.Fail()
	}

	acceptType = ParseAcceptType("text/html;q=0.8")
	if acceptType.Type != "text/html" {
		t.Fail()
	}
	if acceptType.Weight != 0.8 {
		t.Fail()
	}

	acceptType = ParseAcceptType("application/json; q=0.5")
	if acceptType.Type != "application/json" {
		t.Fail()
	}
	if acceptType.Weight != 0.5 {
		t.Fail()
	}

	acceptType = ParseAcceptType("text/html;q=invalid")
	if acceptType.Type != "" {
		t.Fail()
	}
	if acceptType.Weight != 0.0 {
		t.Fail()
	}

	acceptType = ParseAcceptType("*/*")
	if acceptType.Type != "*/*" {
		t.Fail()
	}
	if acceptType.Weight != 1.0 {
		t.Fail()
	}

	acceptType = ParseAcceptType("")
	if acceptType.Type != "" {
		t.Fail()
	}
	if acceptType.Weight != 0.0 {
		t.Fail()
	}
}

func TestParseAcceptHeader(t *testing.T) {
	acceptTypes := ParseAcceptHeader("text/html,application/json")
	if len(acceptTypes) != 2 {
		t.Fail()
	}
	if acceptTypes[0].Type != "text/html" {
		t.Fail()
	}
	if acceptTypes[0].Weight != 1.0 {
		t.Fail()
	}
	if acceptTypes[1].Type != "application/json" {
		t.Fail()
	}
	if acceptTypes[1].Weight != 1.0 {
		t.Fail()
	}

	acceptTypes = ParseAcceptHeader("application/json;q=0.8,text/html;q=0.9")
	if len(acceptTypes) != 2 {
		t.Fail()
	}
	if acceptTypes[0].Type != "text/html" {
		t.Fail()
	}
	if acceptTypes[0].Weight != 0.9 {
		t.Fail()
	}
	if acceptTypes[1].Type != "application/json" {
		t.Fail()
	}
	if acceptTypes[1].Weight != 0.8 {
		t.Fail()
	}

	acceptTypes = ParseAcceptHeader("*/*")
	if len(acceptTypes) != 1 {
		t.Fail()
	}
	if acceptTypes[0].Type != "*/*" {
		t.Fail()
	}
	if acceptTypes[0].Weight != 1.0 {
		t.Fail()
	}
}

func TestIsHtmlRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	if !IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	if IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html, application/json")
	if !IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json;q=0.9, text/html;q=0.8")
	if IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json;q=0.8, text/html;q=0.9")
	if !IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "*/*")
	if IsHtmlRequest(req) {
		t.Fail()
	}

	req, _ = http.NewRequest(http.MethodGet, "/", nil)
	if IsHtmlRequest(req) {
		t.Fail()
	}
}
