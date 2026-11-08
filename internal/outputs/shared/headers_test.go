// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderConstructorValidation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	invalid := filepath.Join(t.TempDir(), "invalid")
	require.NoError(t, os.WriteFile(invalid, []byte("private-file-value\x00"), 0o600))
	tests := []struct {
		name string
		cfg  HTTPConfig
	}{
		{"empty name", HTTPConfig{Headers: map[string]ValueSources{"": {}}}},
		{"space in name", HTTPConfig{Headers: map[string]ValueSources{"X Bad": {}}}},
		{"colon in name", HTTPConfig{Headers: map[string]ValueSources{"X:Bad": {}}}},
		{"control in name", HTTPConfig{Headers: map[string]ValueSources{"X-\r\nBad": {}}}},
		{"nonascii name", HTTPConfig{Headers: map[string]ValueSources{"X-\xff": {}}}},
		{"duplicate names", HTTPConfig{Headers: map[string]ValueSources{"X-Key": {}, "x-key": {}}}},
		{"public controls", HTTPConfig{Headers: map[string]ValueSources{"X-Key": {Values: []string{"private-value\n"}}}}},
		{"secret controls", HTTPConfig{Headers: map[string]ValueSources{"X-Key": {Secrets: []string{"private-value\x7f"}}}}},
		{"missing file", HTTPConfig{Headers: map[string]ValueSources{"X-Key": {Files: []string{missing}}}}},
		{"empty file path", HTTPConfig{Headers: map[string]ValueSources{"X-Key": {Files: []string{""}}}}},
		{"directory", HTTPConfig{Headers: map[string]ValueSources{"X-Key": {Files: []string{t.TempDir()}}}}},
		{"invalid file", HTTPConfig{Headers: map[string]ValueSources{"X-Key": {Files: []string{invalid}}}}},
		{"public authorization", HTTPConfig{Headers: map[string]ValueSources{"aUtHoRiZaTiOn": {Values: []string{"private-value"}}}}},
		{"mixed authorization", HTTPConfig{Headers: map[string]ValueSources{"Authorization": {Values: []string{""}, Secrets: []string{"private-value"}}}}},
		{"bearer conflict", HTTPConfig{BearerToken: "private-bearer", Headers: map[string]ValueSources{"authorization": {Secrets: []string{"private-value"}}}}},
		{"basic conflict", HTTPConfig{Username: "user", Headers: map[string]ValueSources{"Authorization": {Secrets: []string{"private-value"}}}}},
		{"password conflict", HTTPConfig{Password: "private-password", Headers: map[string]ValueSources{"Authorization": {Secrets: []string{"private-value"}}}}},
		{"bearer controls", HTTPConfig{BearerToken: "private-bearer\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSender("test", &tt.cfg)
			require.Error(t, err)
			assert.Nil(t, s)
			assert.NotContains(t, err.Error(), "private-")
		})
	}
}

func TestHeaderTransportOwnedNames(t *testing.T) {
	for _, name := range []string{
		"Host", "Content-Length", "Transfer-Encoding", "Trailer", "Connection",
		"Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization",
		"TE", "Upgrade", "Content-Encoding", "Accept-Encoding",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewSender("test", &HTTPConfig{Headers: map[string]ValueSources{
				strings.ToLower(name): {Values: []string{"private-value"}},
			}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "transport")
			assert.NotContains(t, err.Error(), "private-value")
		})
	}
}

func TestHeaderValueControls(t *testing.T) {
	for b := byte(0); b < 0x80; b++ {
		t.Run(fmt.Sprintf("byte_%02x", b), func(t *testing.T) {
			_, err := NewSender("test", &HTTPConfig{Headers: map[string]ValueSources{
				"X-Key": {Secrets: []string{"private-" + string(b) + "-value"}},
			}})
			if b < 0x20 && b != '\t' || b == 0x7f {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "private-")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestHeaderOrderRotationAndOwnership(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	require.NoError(t, os.WriteFile(first, []byte(" \tfile-one\r\n"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte("file-two\n"), 0o600))
	cfg := HTTPConfig{Headers: map[string]ValueSources{
		"x-key": {Values: []string{"one", "two"}, Secrets: []string{"secret-one", "secret-two"}, Files: []string{first, second}},
	}}
	s, err := NewSender("test", &cfg)
	require.NoError(t, err)
	assert.Contains(t, cfg.Headers, "x-key", "construction must preserve free-form key spelling")
	assert.NotContains(t, cfg.Headers, "X-Key")
	cfg.Headers["x-key"].Values[0] = "changed-public"
	cfg.Headers["x-key"].Secrets[0] = "changed-secret"
	cfg.Headers["x-key"].Files[0] = "changed-path"
	delete(cfg.Headers, "x-key")
	want := []string{"one", "two", "secret-one", "secret-two", "file-one", "file-two"}
	s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, want, req.Header.Values("X-Key"))
		assert.Equal(t, []string{"preserved"}, req.Header.Values("X-Other"))
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)
	req.Header = http.Header{"x-key": {"request-value"}, "X-Other": {"preserved"}}
	original := req.Header.Clone()
	for range 2 {
		require.NoError(t, s.Do(context.Background(), req))
		assert.Equal(t, original, req.Header)
	}
	require.NoError(t, os.WriteFile(first, []byte("rotated\n"), 0o600))
	want[4] = "rotated"
	body, err := s.DoReadBody(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))
	assert.Equal(t, original, req.Header)
}

func TestHeaderFileFailureBeforeDelivery(t *testing.T) {
	for _, mode := range []string{"missing", "invalid", "directory"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")
			require.NoError(t, os.WriteFile(path, []byte("initial"), 0o600))
			s, err := NewSender("test", &HTTPConfig{Headers: map[string]ValueSources{"X-Key": {Files: []string{path}}}})
			require.NoError(t, err)
			s.client.Transport = headerRoundTripper(func(*http.Request) (*http.Response, error) {
				t.Error("invalid headers must not reach transport")
				return nil, fmt.Errorf("unexpected delivery")
			})
			switch mode {
			case "missing":
				require.NoError(t, os.Remove(path))
			case "invalid":
				require.NoError(t, os.WriteFile(path, []byte("private-file-value\r\ninjected"), 0o600))
			case "directory":
				require.NoError(t, os.Remove(path))
				require.NoError(t, os.Mkdir(path, 0o700))
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
			require.NoError(t, err)
			err = s.Do(context.Background(), req)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "files[0]")
			assert.NotContains(t, err.Error(), "private-file-value")
			assert.Empty(t, req.Header)
		})
	}
}

func TestHeaderSetHeaderPrecedence(t *testing.T) {
	s, err := NewSender("test", &HTTPConfig{Headers: map[string]ValueSources{
		"authorization": {Secrets: []string{"configured"}},
		"x-scope-orgid": {Values: []string{"configured"}},
		"content-type":  {Values: []string{"custom/type"}},
		"user-agent":    {Values: []string{"custom-agent"}},
	}})
	require.NoError(t, err)
	s.SetHeader("Authorization", "ApiKey driver")
	s.SetHeader("X-Scope-OrgID", "driver-tenant")
	s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, []string{"ApiKey driver"}, req.Header.Values("Authorization"))
		assert.Equal(t, []string{"driver-tenant"}, req.Header.Values("X-Scope-OrgID"))
		assert.Equal(t, "custom/type", req.Header.Get("Content-Type"))
		assert.Equal(t, "custom-agent", req.Header.Get("User-Agent"))
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	require.NoError(t, s.SendRaw(context.Background(), http.MethodPost, "http://example.com", nil, "application/json"))
}

func TestHeaderConcurrentRequests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, []byte("file-value\n"), 0o600))
	s, err := NewSender("test", &HTTPConfig{Headers: map[string]ValueSources{
		"X-Key": {Values: []string{"public"}, Secrets: []string{"private"}, Files: []string{path}},
	}})
	require.NoError(t, err)
	s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, []string{"public", "private", "file-value"}, req.Header.Values("X-Key"))
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { assert.NoError(t, s.Do(context.Background(), req)) })
	}
	wg.Wait()
	assert.Empty(t, req.Header)
}

func TestApplyHeadersFailureIsAtomic(t *testing.T) {
	req := &http.Request{Header: http.Header{"X-Original": {"unchanged"}}}
	original := req.Header.Clone()
	err := ApplyHeaders(req, map[string]ValueSources{
		"A-Valid": {Values: []string{"value"}},
		"Z-Key":   {Secrets: []string{"private-value\x00"}},
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "private-value")
	assert.Equal(t, original, req.Header)
}

func TestHeaderEmptyValuesAndNilRequestHeaders(t *testing.T) {
	s, err := NewSender("test", &HTTPConfig{Headers: map[string]ValueSources{
		"User-Agent": {},
		"X-Empty":    {Values: []string{""}},
	}})
	require.NoError(t, err)
	s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, userAgent, req.Header.Get("User-Agent"))
		assert.Equal(t, []string{""}, req.Header.Values("X-Empty"))
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com", http.NoBody)
	require.NoError(t, err)
	req.Header = nil
	require.NoError(t, s.Do(context.Background(), req))
	assert.Nil(t, req.Header)
}

func TestHeaderSetHeaderRejectsInvalidValues(t *testing.T) {
	s, err := NewSender("test", &HTTPConfig{})
	require.NoError(t, err)
	s.SetHeader("Authorization", "private-value\n")
	err = s.HealthCheck(context.Background(), "http://example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid header value")
	assert.NotContains(t, err.Error(), "private-value")
}

func TestHeaderRelativeFileStartupValidation(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("key", []byte("protected\n"), 0o600))
	cfg := HTTPConfig{Headers: map[string]ValueSources{"X-Key": {Files: []string{"key"}}}}
	assert.Empty(t, cfg.Validate())
	require.NoError(t, os.Remove("key"))
	_, err := NewSender("test", &cfg)
	require.Error(t, err, "sender construction must recheck previously validated files")

	require.NoError(t, os.WriteFile("key", []byte("protected\n"), 0o600))
	s, err := NewSender("test", &cfg)
	require.NoError(t, err)
	s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, []string{"protected"}, req.Header.Values("X-Key"))
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	require.NoError(t, s.HealthCheck(context.Background(), "http://example.com"))
	assert.Equal(t, []string{"key"}, cfg.Headers["X-Key"].Files)
}

func TestHeaderRedirectForwardingBlocked(t *testing.T) {
	s, err := NewSender("test", &HTTPConfig{
		BearerToken: "builtin-token",
		Headers:     map[string]ValueSources{"X-Api-Key": {Secrets: []string{"custom-token"}}},
	})
	require.NoError(t, err)
	redirected := false
	s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "origin.example.com" {
			return &http.Response{
				StatusCode: http.StatusFound, Body: http.NoBody,
				Header: http.Header{"Location": {"https://destination.example.net"}},
			}, nil
		}
		redirected = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	err = s.HealthCheck(context.Background(), "https://origin.example.com")
	var denied *redirectError
	require.ErrorAs(t, err, &denied)
	assert.Equal(t, "cross-origin redirect denied", denied.Error())
	assert.False(t, redirected, "the destination must not receive any request")
}

type headerRoundTripper func(*http.Request) (*http.Response, error)

func (f headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
