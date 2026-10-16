// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/sync/singleflight"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

const (
	// HostLocalhost is the loopback hostname
	HostLocalhost = "localhost"
	// MaxTokenTTL is the maximum TTL for tokens without expires_in (5 minutes)
	MaxTokenTTL = 5 * time.Minute
	// BackoffMinDuration is the minimum duration for exponential backoff
	BackoffMinDuration = 1 * time.Second
	// BackoffMaxDuration is the maximum duration for exponential backoff
	BackoffMaxDuration = 60 * time.Second
)

// tokenProvider interface for getting tokens
type tokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// isLoopbackHost checks if a hostname is a loopback address
func isLoopbackHost(host string) bool {
	// Check for localhost
	if host == HostLocalhost {
		return true
	}

	// Check for IP address
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// tokenTTLCapper wraps a TokenSource and caps token TTL if Expiry is zero (no expires_in)
type tokenTTLCapper struct {
	source oauth2.TokenSource
}

// Token returns a copy of the token, capping TTL to MaxTokenTTL if Expiry is zero
func (t *tokenTTLCapper) Token() (*oauth2.Token, error) {
	token, err := t.source.Token()
	if err != nil {
		return nil, err
	}

	// If token has no expiry (expires_in was missing), cap it to MaxTokenTTL
	// Return a COPY of the token to avoid race conditions with concurrent Valid() calls
	if token.Expiry.IsZero() {
		t2 := *token
		t2.Expiry = time.Now().Add(MaxTokenTTL)
		return &t2, nil
	}

	return token, nil
}

// clientCredentialsProvider handles OAuth2 client credentials flow with backoff and TTL capping
type clientCredentialsProvider struct {
	source          oauth2.TokenSource
	mu              sync.Mutex
	lastErr         error
	lastErrTime     time.Time
	backoffDuration time.Duration
	backoffAttempts int
	fetching        bool // prevent thundering herd
	group           singleflight.Group
	now             func() time.Time // injectable clock for testing
}

// fileTokenProvider handles reading tokens from a file with cached fallback on errors
type fileTokenProvider struct {
	filePath    string
	mu          sync.RWMutex
	token       string
	mtime       time.Time
	lastStat    time.Time
	lastErrWarn time.Time
}

// newClientCredentialsProvider creates a new OAuth2 client credentials provider
func newClientCredentialsProvider(cfg types.WebUIOAuth2Config) (*clientCredentialsProvider, error) {
	// Validate required fields
	if cfg.TokenURL == "" {
		return nil, errors.New("oauth2: tokenurl is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oauth2: clientid is required")
	}

	// Validate tokenurl uses HTTPS unless loopback
	parsedTokenURL, err := url.Parse(cfg.TokenURL)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to parse tokenurl: %w", err)
	}
	if parsedTokenURL.Scheme != "https" {
		host := parsedTokenURL.Hostname()
		if host == "" || !isLoopbackHost(host) {
			return nil, errors.New("oauth2: tokenurl must use https unless the host is a loopback address (localhost, 127.0.0.1, ::1)")
		}
	}

	// Resolve client secret
	clientSecret := cfg.ClientSecret
	if cfg.ClientSecretFile != "" {
		data, err := os.ReadFile(cfg.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to read clientsecretfile: %w", err)
		}
		clientSecret = strings.TrimSpace(string(data))
	}

	if clientSecret == "" {
		return nil, errors.New("oauth2: clientsecret or clientsecretfile is required")
	}

	// Create TLS config for token endpoint
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Set up root CAs
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	tlsConfig.RootCAs = pool

	// Add custom CA if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to read cafile: %w", err)
		}
		if len(caCert) > 0 && !tlsConfig.RootCAs.AppendCertsFromPEM(caCert) {
			return nil, errors.New("oauth2: failed to append CA certificate")
		}
	}

	// Parse scopes (accept both comma and space-separated)
	var scopes []string
	if cfg.Scopes != "" {
		// Split on both commas and whitespace, drop empty strings
		rawScopes := strings.FieldsFunc(cfg.Scopes, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		})
		scopes = rawScopes
	}

	// Create HTTP client with TLS config and timeout
	// Use DefaultTransport clone to preserve proxy settings, dial timeouts, HTTP/2, etc.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	tokenHTTPClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Build OAuth2 config
	oauth2Config := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: clientSecret,
		TokenURL:     cfg.TokenURL,
		Scopes:       scopes,
	}

	// Add audience and resource parameters if provided
	if cfg.Audience != "" {
		oauth2Config.EndpointParams = make(map[string][]string)
		oauth2Config.EndpointParams.Set("audience", cfg.Audience)
		if cfg.ResourceIndicator {
			oauth2Config.EndpointParams.Set("resource", cfg.Audience)
		}
	}

	// Create token source (clientcredentials.Config.TokenSource already handles caching)
	baseSource := oauth2Config.TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, tokenHTTPClient))

	// Wrap with TTL capper to enforce max 5-minute TTL if expires_in is missing
	// CRITICAL: wrap the capper BEFORE oauth2.ReuseTokenSource to avoid race conditions
	cappedSource := &tokenTTLCapper{source: baseSource}

	// Wrap with ReuseTokenSource for token caching
	reuseSource := oauth2.ReuseTokenSource(nil, cappedSource)

	return &clientCredentialsProvider{
		source:          reuseSource,
		backoffDuration: BackoffMinDuration,
		now:             time.Now,
	}, nil
}

// Token returns the current OAuth2 token with exponential backoff on errors
func (p *clientCredentialsProvider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()

	// Check if we're in backoff period
	if p.lastErr != nil && p.now().Sub(p.lastErrTime) < p.backoffDuration {
		defer p.mu.Unlock()
		// Still in backoff, return the cached error
		return "", fmt.Errorf("oauth2: in backoff period, failed to get token: %w", p.lastErr)
	}

	// If we were in backoff and it expired, but another goroutine is already fetching,
	// return error immediately (keep lastErr set until fetch completes)
	if p.lastErr != nil && p.fetching {
		defer p.mu.Unlock()
		return "", fmt.Errorf("oauth2: fetch in progress, failed to get token: %w", p.lastErr)
	}

	// Backoff window expired and no fetch in progress - mark as fetching
	if p.lastErr != nil {
		p.fetching = true
	}

	p.mu.Unlock()

	// Use singleflight to ensure only one goroutine fetches at a time.
	// All success/failure bookkeeping is done inside this closure so it runs once per fetch.
	tokenInterface, err, _ := p.group.Do("fetch", func() (interface{}, error) {
		token, fetchErr := p.source.Token()

		p.mu.Lock()
		defer p.mu.Unlock()

		if fetchErr != nil {
			// Record error and set backoff
			p.lastErr = fetchErr
			p.lastErrTime = p.now()
			p.backoffAttempts++

			// Exponential backoff: 1s * 2^(min(attempts-1, 6)), capped at 60s
			// Capping the shift at 6 ensures we don't overflow: 2^6 = 64, then capped to 60
			shift := p.backoffAttempts - 1
			if shift > 6 {
				shift = 6
			}
			p.backoffDuration = BackoffMinDuration * time.Duration(1<<uint(shift))
			if p.backoffDuration > BackoffMaxDuration {
				p.backoffDuration = BackoffMaxDuration
			}
			p.fetching = false

			return nil, fmt.Errorf("oauth2: failed to get token (backoff %v): %w", p.backoffDuration, fetchErr)
		}

		// Success, reset backoff and attempts
		p.lastErr = nil
		p.backoffAttempts = 0
		p.backoffDuration = BackoffMinDuration
		p.fetching = false

		return token.AccessToken, nil
	})

	tokenStr, ok := tokenInterface.(string)
	if !ok && tokenInterface != nil {
		tokenStr = ""
	}

	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

// newFileTokenProvider creates a new file-based token provider
func newFileTokenProvider(filePath string) (*fileTokenProvider, error) {
	if filePath == "" {
		return nil, errors.New("tokenfile: path is required")
	}

	provider := &fileTokenProvider{
		filePath: filePath,
	}

	// Read initial token
	if err := provider.refresh(); err != nil {
		return nil, err
	}

	return provider, nil
}

// refresh reads the token from file if it has been updated
func (p *fileTokenProvider) refresh() error {
	// Stat at most every 30s
	now := time.Now()
	p.mu.RLock()
	lastStat := p.lastStat
	oldMTime := p.mtime
	hasToken := p.token != ""
	lastErrWarn := p.lastErrWarn
	p.mu.RUnlock()

	// Check 30s throttle only if we've already read the file
	if !oldMTime.IsZero() && now.Sub(lastStat) < 30*time.Second {
		return nil
	}

	info, err := os.Stat(p.filePath)
	if err != nil {
		// If we have a cached token, log warning (rate-limited) and continue serving it
		if hasToken {
			if now.Sub(lastErrWarn) > 1*time.Minute {
				utils.Log(utils.WarningLvl, "WebUI", fmt.Sprintf("tokenfile: failed to stat file (serving cached token): %v", err))
				p.mu.Lock()
				p.lastErrWarn = now
				p.mu.Unlock()
			}
			p.mu.Lock()
			p.lastStat = now
			p.mu.Unlock()
			return nil
		}
		// No cached token and stat failed, this is a hard error
		return fmt.Errorf("tokenfile: failed to stat file: %w", err)
	}

	newMTime := info.ModTime()

	// Only read if modified (including restored or older files) or not yet read
	if !oldMTime.IsZero() && newMTime.Equal(oldMTime) {
		p.mu.Lock()
		p.lastStat = now
		p.mu.Unlock()
		return nil
	}

	// Read new token
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		// If we have a cached token, log warning and continue serving it
		if hasToken {
			if now.Sub(lastErrWarn) > 1*time.Minute {
				utils.Log(utils.WarningLvl, "WebUI", fmt.Sprintf("tokenfile: failed to read file (serving cached token): %v", err))
				p.mu.Lock()
				p.lastErrWarn = now
				p.mu.Unlock()
			}
			p.mu.Lock()
			p.lastStat = now
			p.mu.Unlock()
			return nil
		}
		// No cached token and read failed, this is a hard error
		return fmt.Errorf("tokenfile: failed to read file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		// Only error if we never successfully read a token before
		if !hasToken {
			return errors.New("tokenfile: file is empty")
		}
		// If we have cached token but new read is empty, keep serving cache
		if now.Sub(lastErrWarn) > 1*time.Minute {
			utils.Log(utils.WarningLvl, "WebUI", "tokenfile: file is now empty (serving cached token)")
			p.mu.Lock()
			p.lastErrWarn = now
			p.mu.Unlock()
		}
		p.mu.Lock()
		p.lastStat = now
		p.mu.Unlock()
		return nil
	}

	p.mu.Lock()
	p.token = token
	p.mtime = newMTime
	p.lastStat = now
	p.mu.Unlock()

	return nil
}

// Token returns the current token from file
func (p *fileTokenProvider) Token(ctx context.Context) (string, error) {
	err := p.refresh()

	// Even if refresh fails, try to return cached token if available
	p.mu.RLock()
	cachedToken := p.token
	p.mu.RUnlock()

	if cachedToken != "" {
		return cachedToken, nil
	}

	// No cached token available
	if err != nil {
		return "", err
	}

	// No token and no error from refresh means file was empty on first read
	return "", errors.New("tokenfile: no token available")
}

// ValidateWebUIAuth validates OAuth2 and TokenFile configuration
func ValidateWebUIAuth(config types.WebUIOutputConfig) (tokenProvider, error) {
	hasOAuth2 := config.OAuth2.TokenURL != ""
	hasTokenFile := config.TokenFile != ""

	// Check for conflicting configuration
	if hasOAuth2 && hasTokenFile {
		return nil, errors.New("webui: cannot configure both oauth2 and tokenfile")
	}

	// If neither is configured, return nil (no auth)
	if !hasOAuth2 && !hasTokenFile {
		return nil, nil
	}

	// Configure OAuth2
	if hasOAuth2 {
		provider, err := newClientCredentialsProvider(config.OAuth2)
		if err != nil {
			return nil, fmt.Errorf("webui: %w", err)
		}
		return provider, nil
	}

	// Configure token file
	provider, err := newFileTokenProvider(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("webui: %w", err)
	}
	return provider, nil
}

// WarnIfPlaintextWebUIURL warns if a token source is configured but the UI URL uses plaintext HTTP (unless loopback)
func WarnIfPlaintextWebUIURL(rawURL string, hasAuth bool) {
	if !hasAuth {
		return
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	// Check if URL uses HTTPS or is a loopback address
	if strings.EqualFold(parsedURL.Scheme, "https") {
		return
	}
	if isLoopbackHost(parsedURL.Hostname()) {
		return
	}

	// Log warning for plaintext HTTP (but don't block, for service mesh deployments)
	utils.Log(utils.WarningLvl, "WebUI", "bearer token sent over plaintext HTTP; use TLS or a service mesh")
}
