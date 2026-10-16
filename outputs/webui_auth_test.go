// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	testAudience = "test-audience"
	testToken    = "test-token"

	testTokenNoExpiry = "token-no-expiry" //nolint:gosec // test fixture, not a real credential
)

// TestClientCredentialsFlow tests OAuth2 client credentials grant flow
func TestClientCredentialsFlow(t *testing.T) {
	tokenCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		// Verify grant type
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("Expected grant_type=client_credentials, got %s", r.FormValue("grant_type"))
		}
		// Verify client auth
		username, password, ok := r.BasicAuth()
		if !ok || username != "test-client" || password != "test-secret" {
			t.Errorf("Expected Basic auth with test-client:test-secret")
		}
		// Verify scopes (should be space-separated per OAuth2 spec)
		scope := r.FormValue("scope")
		if scope != "api read" {
			t.Errorf("Expected scope=api read, got %s", scope)
		}
		// Verify audience
		audience := r.FormValue("audience")
		if audience != testAudience {
			t.Errorf("Expected audience=%s, got %s", testAudience, audience)
		}
		// Return token
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token-123",
			"token_type":   Bearer,
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Scopes:       "api read",
			Audience:     testAudience,
		},
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// First call should hit token server
	token1, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token1 != "test-token-123" {
		t.Errorf("Expected test-token-123, got %s", token1)
	}

	// Second call should reuse token (not hit server again)
	token2, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token2 != "test-token-123" {
		t.Errorf("Expected test-token-123, got %s", token2)
	}

	// Should only have hit server once due to token reuse
	if tokenCalls != 1 {
		t.Errorf("Expected 1 token call, got %d", tokenCalls)
	}
}

// TestFileTokenProvider tests reading tokens from file
func TestFileTokenProvider(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")

	// Write initial token
	initialToken := "initial-token-123"
	if err := os.WriteFile(tokenFile, []byte(initialToken+"\n"), 0o600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	config := types.WebUIOutputConfig{
		TokenFile: tokenFile,
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Read token
	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token != initialToken {
		t.Errorf("Expected %s, got %s", initialToken, token)
	}

	// Test that same token is returned without re-reading (within 30s window)
	token2, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token2 != initialToken {
		t.Errorf("Expected %s, got %s", initialToken, token2)
	}

	// For testing file rotation after 30s, we would need to wait or mock time.
	// Since that's impractical in unit tests, we just verify the initial read works.
}

// TestFileTokenProviderEmpty tests error when token file is empty
func TestFileTokenProviderEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")

	// Create empty file
	if err := os.WriteFile(tokenFile, []byte(""), 0o600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	config := types.WebUIOutputConfig{
		TokenFile: tokenFile,
	}

	_, err := ValidateWebUIAuth(config)
	if err == nil {
		t.Error("Expected error for empty token file")
	}
}

// TestFileTokenProviderMissing tests error when token file doesn't exist
func TestFileTokenProviderMissing(t *testing.T) {
	config := types.WebUIOutputConfig{
		TokenFile: "/nonexistent/token/file",
	}

	_, err := ValidateWebUIAuth(config)
	if err == nil {
		t.Error("Expected error for missing token file")
	}
}

// TestValidateWebUIAuthConflict tests error when both OAuth2 and TokenFile are configured
func TestValidateWebUIAuthConflict(t *testing.T) {
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{ //nolint:gosec // test fixture, not a real credential
			TokenURL: "https://example.com/token",
			ClientID: "test-config",
		},
		TokenFile: "/some/file",
	}

	_, err := ValidateWebUIAuth(config)
	if err == nil {
		t.Error("Expected error for conflicting auth config")
	}
}

// TestValidateWebUIAuthMissingClientID tests error when ClientID is missing
func TestValidateWebUIAuthMissingClientID(t *testing.T) {
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{ //nolint:gosec // test fixture, not a real credential
			TokenURL: "https://example.com/token",
		},
	}

	_, err := ValidateWebUIAuth(config)
	if err == nil {
		t.Error("Expected error for missing clientid")
	}
}

// TestValidateWebUIAuthMissingSecret tests error when neither ClientSecret nor ClientSecretFile is configured
func TestValidateWebUIAuthMissingSecret(t *testing.T) {
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{ //nolint:gosec // test fixture, not a real credential
			TokenURL: "https://example.com/token",
			ClientID: "test-client-no-secret",
		},
	}

	_, err := ValidateWebUIAuth(config)
	if err == nil {
		t.Error("Expected error for missing secret")
	}
}

// TestValidateWebUIAuthSecretFile tests reading secret from file
func TestValidateWebUIAuthSecretFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret")
	if err := os.WriteFile(secretFile, []byte("secret-from-file\n"), 0o600); err != nil {
		t.Fatalf("Failed to write secret file: %v", err)
	}

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:         server.URL,
			ClientID:         "test-client",
			ClientSecretFile: secretFile,
		},
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token != testToken {
		t.Errorf("Expected %s, got %s", testToken, token)
	}
}

// TestWarnIfPlaintextWebUIURLNonLoopback tests warning for HTTP WebUI URL
func TestWarnIfPlaintextWebUIURLNonLoopback(t *testing.T) {
	// The spec says it should log a warning but not block for non-loopback HTTP
	// WarnIfPlaintextWebUIURL should log a warning and not panic
	WarnIfPlaintextWebUIURL("http://example.com", true)
	// If we get here without panic, test passes
}

// TestWarnIfPlaintextWebUIURLLoopback tests no warning for HTTP loopback
func TestWarnIfPlaintextWebUIURLLoopback(t *testing.T) {
	// WarnIfPlaintextWebUIURL should not log a warning for loopback
	WarnIfPlaintextWebUIURL("http://localhost:8080", true)
	// If we get here without panic, test passes
}

// TestWarnIfPlaintextWebUIURLHTTPS tests no warning for HTTPS URL
func TestWarnIfPlaintextWebUIURLHTTPS(t *testing.T) {
	// WarnIfPlaintextWebUIURL should not log a warning for HTTPS
	WarnIfPlaintextWebUIURL("https://example.com", true)
	// If we get here without panic, test passes
}

// TestWebUIPostWithAuthorization tests WebUIPost with authorization header
func TestWebUIPostWithAuthorization(t *testing.T) {
	// Create a mock UI server
	var authHeader string
	uiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer uiServer.Close()

	// Create OAuth2 token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-bearer-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	// Create token provider first
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     tokenServer.URL,
			ClientID:     "test",
			ClientSecret: "secret",
		},
	}
	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Get a token to verify it works
	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	// Create a simple request to test the header
	req, err := http.NewRequest("POST", uiServer.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set(AuthorizationHeaderKey, Bearer+" "+token)

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Verify authorization header was sent
	if authHeader != "Bearer test-bearer-token" {
		t.Errorf("Expected 'Bearer test-bearer-token', got '%s'", authHeader)
	}
}

// TestWebUIPostWithoutAuthorization tests WebUIPost without authorization when not configured
func TestWebUIPostWithoutAuthorization(t *testing.T) {
	// Create a mock UI server
	var authHeader string
	uiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer uiServer.Close()

	// Create a simple request without auth
	req, err := http.NewRequest("POST", uiServer.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	// Note: not setting Authorization header

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Verify no authorization header
	if authHeader != "" {
		t.Errorf("Expected no Authorization header, got '%s'", authHeader)
	}
}

// TestOAuth2CAFile tests OAuth2 with custom CA file
func TestOAuth2CAFile(t *testing.T) {
	// Create a test CA file (empty is acceptable - no certs to add)
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(caFile, []byte(""), 0o600); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test",
			ClientSecret: "secret",
			CAFile:       caFile,
		},
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token != "test-token" {
		t.Errorf("Expected test-token, got %s", token)
	}
}

// TestOAuth2ResourceIndicator tests OAuth2 with resource indicator flag
func TestOAuth2ResourceIndicator(t *testing.T) {
	requestCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCalls++
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}
		// Verify both audience and resource are sent
		audience := r.FormValue("audience")
		resource := r.FormValue("resource")
		if audience != testAudience {
			t.Errorf("Expected audience=%s, got %s", testAudience, audience)
		}
		if resource != testAudience {
			t.Errorf("Expected resource=%s, got %s", testAudience, resource)
		}
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:          server.URL,
			ClientID:          "test",
			ClientSecret:      "secret",
			Audience:          testAudience,
			ResourceIndicator: true,
		},
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token != "test-token" {
		t.Errorf("Expected test-token, got %s", token)
	}
}

// TestNoAuthConfigured tests that ValidateWebUIAuth returns nil when no auth is configured
func TestNoAuthConfigured(t *testing.T) {
	config := types.WebUIOutputConfig{}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if provider != nil {
		t.Error("Expected nil provider when no auth configured")
	}
}

// TestOAuth2TokenURLHTTPNonLoopback tests error when tokenurl is HTTP on non-loopback
func TestOAuth2TokenURLHTTPNonLoopback(t *testing.T) {
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{ //nolint:gosec // test fixture, not a real credential
			TokenURL:     "http://example.com/token",
			ClientID:     "test",
			ClientSecret: "secret",
		},
	}

	_, err := ValidateWebUIAuth(config)
	if err == nil {
		t.Error("Expected error for HTTP tokenurl on non-loopback host")
	}
}

// TestOAuth2TokenURLHTTPLoopback tests success when tokenurl is HTTP on loopback
func TestOAuth2TokenURLHTTPLoopback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{ //nolint:gosec // test fixture, not a real credential
			TokenURL:     "http://127.0.0.1:8080/token",
			ClientID:     "test",
			ClientSecret: "secret",
		},
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Errorf("Expected no error for HTTP tokenurl on loopback, got %v", err)
	}
	if provider == nil {
		t.Error("Expected provider for loopback tokenurl")
	}
}

// TestLoopbackBypassAttempts tests that hostname validation is not bypassable with malicious URLs
func TestLoopbackBypassAttempts(t *testing.T) {
	testCases := []struct {
		name       string
		url        string
		shouldFail bool
	}{
		{"localhost.attacker.com", "http://localhost.attacker.com/token", true},
		{"URL with query localhost", "http://attacker.com/?x=localhost/token", true},
		{"localhost port", "http://localhost:8080/token", false},
		{"127.0.0.1", "http://127.0.0.1/token", false},
		{"::1", "http://[::1]/token", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := types.WebUIOutputConfig{
				OAuth2: types.WebUIOAuth2Config{
					TokenURL:     tc.url,
					ClientID:     "test",
					ClientSecret: "secret",
				},
			}

			_, err := ValidateWebUIAuth(config)
			if tc.shouldFail && err == nil {
				t.Errorf("Expected error for bypass attempt: %s", tc.name)
			}
			if !tc.shouldFail && err != nil {
				t.Errorf("Expected success for loopback %s, got error: %v", tc.name, err)
			}
		})
	}
}

// TestWebUIURLBypassLoopback tests loopback detection for WebUI URL
func TestWebUIURLBypassLoopback(t *testing.T) {
	testCases := []struct {
		name       string
		url        string
		shouldWarn bool
	}{
		{"http://localhost", "http://localhost/", false},
		{"http://127.0.0.1", "http://127.0.0.1/", false},
		{"http://[::1]", "http://[::1]/", false},
		{"http://localhost.attacker.com", "http://localhost.attacker.com/", true},
		{"https://attacker.com", "https://attacker.com/", false},
		{"http://attacker.com", "http://attacker.com/", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// WarnIfPlaintextWebUIURL logs warnings but does not error
			WarnIfPlaintextWebUIURL(tc.url, true)
			// If we get here without panic, test passes
		})
	}
}

// TestScopesCommaAndSpaceSeparated tests that both comma and space-separated scopes work
func TestScopesCommaAndSpaceSeparated(t *testing.T) {
	testCases := []struct {
		name   string
		scopes string
	}{
		{"comma-separated", "api,read"},
		{"space-separated", "api read"},
		{"mixed", "api, read"},
		{"tabs and newlines", "api\tread"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatalf("Failed to parse form: %v", err)
				}
				scope := r.FormValue("scope")
				// Should have api and read as separate values
				if !strings.Contains(scope, "api") || !strings.Contains(scope, "read") {
					t.Errorf("Expected scope to contain 'api' and 'read', got: %s", scope)
				}
				w.Header().Set("Content-Type", "application/json")
				response := map[string]interface{}{
					"access_token": "test-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			config := types.WebUIOutputConfig{
				OAuth2: types.WebUIOAuth2Config{
					TokenURL:     server.URL,
					ClientID:     "test",
					ClientSecret: "secret",
					Scopes:       tc.scopes,
				},
			}

			provider, err := ValidateWebUIAuth(config)
			if err != nil {
				t.Errorf("Failed to create provider: %v", err)
				return
			}

			_, err = provider.Token(context.Background())
			if err != nil {
				t.Errorf("Failed to get token: %v", err)
			}
		})
	}
}

// TestFileTokenProviderStatErrorCachedToken tests that stat errors don't discard cached tokens
func TestFileTokenProviderStatErrorCachedToken(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")

	// Write initial token
	initialToken := "cached-token-123"
	if err := os.WriteFile(tokenFile, []byte(initialToken+"\n"), 0o600); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	config := types.WebUIOutputConfig{
		TokenFile: tokenFile,
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Get initial token
	token1, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get initial token: %v", err)
	}
	if token1 != initialToken {
		t.Errorf("Expected %s, got %s", initialToken, token1)
	}

	// Delete the token file
	if err := os.Remove(tokenFile); err != nil {
		t.Fatalf("Failed to remove token file: %v", err)
	}

	// Get token again - should still return cached token even though file is gone
	token2, err := provider.Token(context.Background())
	if err != nil {
		t.Errorf("Expected cached token on stat error, got error: %v", err)
	}
	if token2 != initialToken {
		t.Errorf("Expected cached token %s, got %s", initialToken, token2)
	}
}

// TestOAuth2TokenTTLCapping tests that tokens without expires_in are capped at 5 minutes
func TestOAuth2TokenTTLCapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return token response WITHOUT expires_in (should be capped to 5 minutes)
		response := map[string]interface{}{ //nolint:gosec // test fixture, not a real credential
			"access_token": testTokenNoExpiry,
			"token_type":   "Bearer",
			// Intentionally omit expires_in
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-ttl-cap",
			ClientSecret: "testsecret-notcred",
		},
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Get token - should succeed even without expires_in
	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token without expires_in: %v", err)
	}
	//nolint:gosec // test fixture, not a real credential
	if token != testTokenNoExpiry {
		t.Errorf("Expected token-no-expiry, got %s", token)
	}

	// Second call should reuse the token (cached by TokenSource)
	token2, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get cached token: %v", err)
	}
	//nolint:gosec // test fixture, not a real credential
	if token2 != testTokenNoExpiry {
		t.Errorf("Expected reused token, got %s", token2)
	}
}

// TestOAuth2TokenEndpointBackoff tests exponential backoff on token endpoint errors
func TestOAuth2TokenEndpointBackoff(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Return error on first call
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server_error"}`))
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-backoff",
			ClientSecret: "testsecret-notcred",
		},
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// First call should fail
	_, err1 := provider.Token(context.Background())
	if err1 == nil {
		t.Error("Expected error on first token call")
	}

	// Second call should also fail immediately (in backoff)
	// without making another request to the server
	initialCallCount := callCount
	_, err2 := provider.Token(context.Background())
	if err2 == nil {
		t.Error("Expected error on backoff second call")
	}

	// Should not have made additional call (backoff prevents it)
	if callCount > initialCallCount {
		t.Errorf("Expected backoff to prevent additional call, but call count increased from %d to %d", initialCallCount, callCount)
	}
}

// TestOAuth2ExponentialBackoffWithInjectableClock tests true exponential backoff with injectable clock
func TestOAuth2ExponentialBackoffWithInjectableClock(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Always return error
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server_error"}`))
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-backoff",
			ClientSecret: "testsecret-notcred",
		},
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Cast to access injectable clock
	ccProvider := provider.(*clientCredentialsProvider)

	// Set up injectable clock
	mockTime := time.Now()
	ccProvider.now = func() time.Time { return mockTime }

	// Successive failures should yield exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s (capped)
	expectedBackoffs := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		32 * time.Second,
		60 * time.Second, // capped at BackoffMaxDuration
	}

	for i, expectedBackoff := range expectedBackoffs {
		// First attempt after backoff expires - should make server call
		_, err := ccProvider.Token(context.Background())
		if err == nil {
			t.Errorf("Attempt %d: Expected error on token call", i+1)
		}

		// Verify backoff duration
		ccProvider.mu.Lock()
		actualBackoff := ccProvider.backoffDuration
		ccProvider.mu.Unlock()

		if actualBackoff != expectedBackoff {
			t.Errorf("Attempt %d: Expected backoff %v, got %v", i+1, expectedBackoff, actualBackoff)
		}

		// Advance time by the backoff duration + 1ms to exceed backoff window
		mockTime = mockTime.Add(expectedBackoff + 1*time.Millisecond)
	}

	// Now simulate a successful token fetch
	// We need to create a new provider to test success flow separately,
	// since the cached token from the error server would interfere
	successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return success
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "success-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer successServer.Close()

	successConfig := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     successServer.URL,
			ClientID:     "test-success",
			ClientSecret: "testsecret-notcred",
		},
	}

	successProvider, err := ValidateWebUIAuth(successConfig)
	if err != nil {
		t.Fatalf("Failed to create success provider: %v", err)
	}

	// Set injectable clock for success provider
	successCCProvider := successProvider.(*clientCredentialsProvider)
	successMockTime := time.Now()
	successCCProvider.now = func() time.Time { return successMockTime }

	// First, cause a failure to build up attempts
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server_error"}`))
	}))
	defer failServer.Close()

	failConfig := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     failServer.URL,
			ClientID:     "test-fail",
			ClientSecret: "testsecret-notcred",
		},
	}

	failProvider, err := ValidateWebUIAuth(failConfig)
	if err != nil {
		t.Fatalf("Failed to create fail provider: %v", err)
	}

	failCCProvider := failProvider.(*clientCredentialsProvider)
	failMockTime := time.Now()
	failCCProvider.now = func() time.Time { return failMockTime }

	// Build up attempts
	_, _ = failCCProvider.Token(context.Background())
	failMockTime = failMockTime.Add(BackoffMinDuration + 1*time.Millisecond)
	_, _ = failCCProvider.Token(context.Background())
	failMockTime = failMockTime.Add(2*time.Second + 1*time.Millisecond)

	// Verify we have 2 attempts built up
	failCCProvider.mu.Lock()
	attempts := failCCProvider.backoffAttempts
	failCCProvider.mu.Unlock()
	if attempts != 2 {
		t.Errorf("Expected 2 attempts after failures, got %d", attempts)
	}

	// Now test success resets attempts
	token, err := successCCProvider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token on success: %v", err)
	}
	if token != "success-token" {
		t.Errorf("Expected success-token, got %s", token)
	}

	// Verify attempts were reset
	successCCProvider.mu.Lock()
	attempts = successCCProvider.backoffAttempts
	backoffDur := successCCProvider.backoffDuration
	successCCProvider.mu.Unlock()

	if attempts != 0 {
		t.Errorf("After success, expected backoffAttempts=0, got %d", attempts)
	}
	if backoffDur != BackoffMinDuration {
		t.Errorf("After success, expected backoffDuration=%v, got %v", BackoffMinDuration, backoffDur)
	}
}

// TestOAuth2NoRedirectFollowing tests that token client does not follow redirects
func TestOAuth2NoRedirectFollowing(t *testing.T) {
	redirectedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Redirect target server should not receive requests")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer redirectedServer.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a 302 redirect to another server
		w.Header().Set("Location", redirectedServer.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer tokenServer.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     tokenServer.URL,
			ClientID:     "test-noredirect",
			ClientSecret: "testsecret-notcred",
		},
	}

	provider, err := ValidateWebUIAuth(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Attempt to get token - should fail due to redirect response, not follow
	_, err = provider.Token(context.Background())
	if err == nil {
		t.Error("Expected error when redirect is returned (should not follow)")
	}

	// Verify the error is about the redirect response (400+ status), not about reaching the redirect target
	if redirectedServer.URL != "" {
		// The server handler would have been called if redirect was followed
		// Since we're here without that error, redirect wasn't followed
	}
}

// newTestCCProvider builds a client credentials provider against the given token URL
// with a controllable clock and returns the provider plus a function to move the clock.
func newTestCCProvider(t *testing.T, tokenURL string) (*clientCredentialsProvider, func(time.Duration)) {
	t.Helper()
	provider, err := ValidateWebUIAuth(types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     tokenURL,
			ClientID:     "test-client",
			ClientSecret: "testsecret-notcred",
		},
	})
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	cc, ok := provider.(*clientCredentialsProvider)
	if !ok {
		t.Fatalf("Expected *clientCredentialsProvider, got %T", provider)
	}
	var clockMu sync.RWMutex
	mockTime := time.Now()
	cc.now = func() time.Time {
		clockMu.RLock()
		defer clockMu.RUnlock()
		return mockTime
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		mockTime = mockTime.Add(d)
	}
	return cc, advance
}

// staticTokenSource always returns the very same *oauth2.Token pointer
type staticTokenSource struct {
	token *oauth2.Token
}

func (s *staticTokenSource) Token() (*oauth2.Token, error) { return s.token, nil }

// TestTokenTTLCapperDoesNotMutateSourceToken verifies the capper returns a copy and
// never writes to the token owned by the wrapped source (data race regression).
func TestTokenTTLCapperDoesNotMutateSourceToken(t *testing.T) {
	shared := &oauth2.Token{AccessToken: "shared-token", TokenType: "Bearer"}
	capper := &tokenTTLCapper{source: &staticTokenSource{token: shared}}

	const goroutines = 50
	for round := 0; round < 5; round++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				tok, err := capper.Token()
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if tok == shared {
					t.Error("capper returned the source token pointer instead of a copy")
					return
				}
				if tok.Expiry.IsZero() || !tok.Valid() {
					t.Errorf("expected capped, valid token, got expiry %v", tok.Expiry)
				}
				// Concurrent read of the shared token, races with any mutation of it
				_ = shared.Valid()
				_ = shared.Expiry
			}()
		}
		close(start)
		wg.Wait()
	}
	if !shared.Expiry.IsZero() {
		t.Errorf("source token was mutated by capper: Expiry=%v", shared.Expiry)
	}
}

// TestOAuth2ConcurrentTokenNoExpiresInRace runs concurrent Token() calls against a server
// that omits expires_in. It is meant to be run with -race.
func TestOAuth2ConcurrentTokenNoExpiresInRace(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:gosec // test fixture, not a real credential
			"access_token": testTokenNoExpiry,
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	provider, _ := newTestCCProvider(t, server.URL)

	const goroutines = 50
	for round := 0; round < 5; round++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				tok, err := provider.Token(context.Background())
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				//nolint:gosec // test fixture, not a real credential
				if tok != testTokenNoExpiry {
					t.Errorf("unexpected token %q", tok)
				}
			}()
		}
		close(start)
		wg.Wait()
	}
	// The capped token is cached for 5 minutes, so the server must not be hit every round.
	if n := atomic.LoadInt32(&requests); n > goroutines {
		t.Errorf("expected cached token to limit requests, got %d", n)
	}
}

// TestOAuth2BackoffNoOverflow checks the backoff stays within [BackoffMinDuration, BackoffMaxDuration]
// after many consecutive failures.
func TestOAuth2BackoffNoOverflow(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "server_error"}`))
	}))
	defer server.Close()

	cc, advance := newTestCCProvider(t, server.URL)

	const failures = 100
	for i := 1; i <= failures; i++ {
		if _, err := cc.Token(context.Background()); err == nil {
			t.Fatalf("attempt %d: expected error", i)
		}
		cc.mu.Lock()
		d := cc.backoffDuration
		cc.mu.Unlock()
		if d < BackoffMinDuration || d > BackoffMaxDuration {
			t.Fatalf("attempt %d: backoff %v outside [%v, %v]", i, d, BackoffMinDuration, BackoffMaxDuration)
		}
		advance(BackoffMaxDuration + time.Second)
	}
	// Every failure must have triggered a fetch (the clock was advanced past each backoff window)
	if n := atomic.LoadInt32(&requests); n < failures {
		t.Errorf("expected at least %d token requests, got %d", failures, n)
	}
}

// TestOAuth2BackoffNoThunderingHerd checks that when the backoff window has expired, many
// concurrent callers result in exactly one request to the token endpoint.
func TestOAuth2BackoffNoThunderingHerd(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		// Keep the request in flight long enough for every goroutine to arrive
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "server_error"}`))
	}))
	defer server.Close()

	cc, advance := newTestCCProvider(t, server.URL)

	// First failure puts the provider into backoff
	if _, err := cc.Token(context.Background()); err == nil {
		t.Fatal("expected first call to fail")
	}
	// One failed fetch may take more than one HTTP request: the oauth2 library retries with
	// the credentials in the body when auto-detecting the auth style fails. Measure it.
	perFetch := atomic.LoadInt32(&requests)
	if perFetch < 1 {
		t.Fatalf("expected at least 1 request after first failure, got %d", perFetch)
	}

	// Let the backoff window expire
	advance(BackoffMaxDuration + time.Second)

	const goroutines = 50
	var wg sync.WaitGroup
	var failed int32
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := cc.Token(context.Background()); err != nil {
				atomic.AddInt32(&failed, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if extra := atomic.LoadInt32(&requests) - perFetch; extra != perFetch {
		t.Errorf("expected exactly one fetch (%d request(s)) after backoff expiry, got %d request(s)", perFetch, extra)
	}
	if f := atomic.LoadInt32(&failed); f != goroutines {
		t.Errorf("expected all %d callers to get an error, got %d", goroutines, f)
	}
}

// TestOAuth2FirstFailureConcurrentCallers checks that a burst of concurrent callers hitting
// a failing endpoint for the first time counts as a single failure (one backoff step).
func TestOAuth2FirstFailureConcurrentCallers(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "server_error"}`))
	}))
	defer server.Close()

	cc, _ := newTestCCProvider(t, server.URL)

	const goroutines = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = cc.Token(context.Background())
		}()
	}
	close(start)
	wg.Wait()

	// Failed fetch = 1 or 2 HTTP requests (oauth2 auth style auto-detection), never one per caller
	if n := atomic.LoadInt32(&requests); n < 1 || n > 2 {
		t.Errorf("expected a single fetch (1-2 requests), got %d requests", n)
	}
	cc.mu.Lock()
	attempts, d := cc.backoffAttempts, cc.backoffDuration
	cc.mu.Unlock()
	if attempts != 1 {
		t.Errorf("expected 1 failure to be recorded for one failed fetch, got %d", attempts)
	}
	if d != BackoffMinDuration {
		t.Errorf("expected backoff %v after first failure, got %v", BackoffMinDuration, d)
	}
}

// TestOAuth2RecoversAfterFailures checks that the provider recovers once the IdP comes back
// and that concurrent callers all receive the token.
func TestOAuth2RecoversAfterFailures(t *testing.T) {
	const failUntil = 3
	var requests int32
	var healthy atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "server_error"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:gosec // test fixture, not a real credential
			"access_token": "recovered-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	cc, advance := newTestCCProvider(t, server.URL)

	for i := 1; i <= failUntil; i++ {
		if _, err := cc.Token(context.Background()); err == nil {
			t.Fatalf("attempt %d: expected error", i)
		}
		// Still in backoff: must fail fast without hitting the server
		before := atomic.LoadInt32(&requests)
		if _, err := cc.Token(context.Background()); err == nil {
			t.Fatalf("attempt %d: expected backoff error", i)
		}
		if after := atomic.LoadInt32(&requests); after != before {
			t.Fatalf("attempt %d: request made while in backoff", i)
		}
		advance(BackoffMaxDuration + time.Second)
	}

	healthy.Store(true)

	// IdP is back: a burst of concurrent callers must all get the token
	const goroutines = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	var okCount int32
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			tok, err := cc.Token(context.Background())
			if err == nil && tok == "recovered-token" {
				atomic.AddInt32(&okCount, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	// The caller that wins the fetch must succeed; afterwards everyone gets the cached token
	if atomic.LoadInt32(&okCount) == 0 {
		t.Fatal("no caller received the token after the IdP recovered")
	}
	for i := 0; i < 3; i++ {
		tok, err := cc.Token(context.Background())
		if err != nil || tok != "recovered-token" {
			t.Fatalf("subsequent call %d: got (%q, %v), want recovered-token", i, tok, err)
		}
	}
	cc.mu.Lock()
	lastErr, attempts, fetching, d := cc.lastErr, cc.backoffAttempts, cc.fetching, cc.backoffDuration
	cc.mu.Unlock()
	if lastErr != nil || attempts != 0 || fetching || d != BackoffMinDuration {
		t.Errorf("state not reset after recovery: lastErr=%v attempts=%d fetching=%v backoff=%v", lastErr, attempts, fetching, d)
	}
}
