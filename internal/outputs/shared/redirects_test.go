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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedirectOrigins(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		location string
		allowed  bool
	}{
		{"relative", "https://example.com/start", "/end", true},
		{"absolute", "https://example.com/start", "https://example.com/end", true},
		{"host case", "https://EXAMPLE.com/start", "https://example.COM/end", true},
		{"https default port", "https://example.com/start", "https://example.com:443/end", true},
		{"http default port", "http://example.com:80/start", "http://example.com/end", true},
		{"port leading zeros", "https://example.com:00443/start", "https://example.com/end", true},
		{"idna", "https://b\u00fccher.example/start", "https://xn--bcher-kva.example/end", true},
		{"idna reverse", "https://xn--bcher-kva.example/start", "https://b\u00fccher.example/end", true},
		{"ipv6", "https://[2001:db8::1]/start", "https://[2001:0DB8:0:0:0:0:0:1]:443/end", true},
		{"ipv6 zone", "http://[fe80::1%25en0]/start", "http://[fe80:0:0:0:0:0:0:1%25en0]:80/end", true},
		{"other host", "https://example.com/start", "https://other.example/end", false},
		{"subdomain", "https://example.com/start", "https://sub.example.com/end", false},
		{"suffix lookalike", "https://example.com/start", "https://notexample.com/end", false},
		{"other port", "https://example.com/start", "https://example.com:8443/end", false},
		{"downgrade", "https://example.com/start", "http://example.com/end", false},
		{"upgrade", "http://example.com/start", "https://example.com/end", false},
		{"scheme relative", "https://example.com/start", "//other.example/end", false},
		{"ip alias", "http://localhost/start", "http://127.0.0.1/end", false},
		{"ipv6 other zone", "http://[fe80::1%25en0]/start", "http://[fe80::1%25EN0]/end", false},
		{"unsupported scheme", "https://example.com/start", "ftp://example.com/end", false},
		{"opaque URL", "https://example.com/start", "https:opaque-secret", false},
		{"invalid port", "https://example.com/start", "https://example.com:65536/end", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := BuildHTTPClient(&HTTPConfig{})
			require.NoError(t, err)
			require.Nil(t, client.Jar)
			calls := 0
			body := &redirectResponseBody{}
			client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))
				assert.Equal(t, "session=secret", req.Header.Get("Cookie"))
				assert.Equal(t, []string{"public", "secret"}, req.Header.Values("X-Key"))
				if calls == 1 {
					resp := redirectResponse(req, http.StatusTemporaryRedirect, tt.location)
					resp.Body = body
					return resp, nil
				}
				return redirectResponse(req, http.StatusOK, ""), nil
			})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tt.origin, http.NoBody)
			require.NoError(t, err)
			req.Header = http.Header{
				"Authorization": {"Bearer token"}, "Cookie": {"session=secret"}, "X-Key": {"public", "secret"},
			}
			original := req.Header.Clone()
			resp, err := client.Do(req)
			if tt.allowed {
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				assert.Equal(t, 2, calls)
			} else {
				var denied *redirectError
				require.ErrorAs(t, err, &denied)
				assert.NotContains(t, denied.Error(), "example")
				assert.NotContains(t, denied.Error(), "secret")
				assert.Equal(t, 1, calls, "denied destination must never reach transport")
			}
			assert.True(t, body.closed)
			assert.Equal(t, original, req.Header)
		})
	}
}

func TestRedirectMethodsAndBodies(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			for _, payload := range []string{"", "event-body"} {
				t.Run(fmt.Sprintf("%d/%s/body=%t", status, method, payload != ""), func(t *testing.T) {
					client, err := BuildHTTPClient(&HTTPConfig{})
					require.NoError(t, err)
					calls := 0
					client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
						calls++
						assert.Equal(t, method, req.Method)
						if req.Body != nil {
							body, readErr := io.ReadAll(req.Body)
							assert.NoError(t, readErr)
							assert.Equal(t, payload, string(body))
							assert.NoError(t, req.Body.Close())
						}
						if calls == 1 {
							return redirectResponse(req, status, "/end"), nil
						}
						return redirectResponse(req, http.StatusOK, ""), nil
					})
					req, err := http.NewRequestWithContext(context.Background(), method, "https://example.com/start", strings.NewReader(payload))
					require.NoError(t, err)
					resp, err := client.Do(req)
					allowed := status == 307 || status == 308 || payload == "" && (method == http.MethodGet || method == http.MethodHead)
					if allowed {
						require.NoError(t, err)
						require.NoError(t, resp.Body.Close())
						assert.Equal(t, 2, calls)
					} else {
						var denied *redirectError
						require.ErrorAs(t, err, &denied)
						assert.Equal(t, "redirect would change delivery method or body", denied.reason)
						assert.Equal(t, 1, calls)
					}
				})
			}
		}
	}
}

func TestSenderRedirectPayloads(t *testing.T) {
	jsonBody := []byte(`{"rule":"event","output":"keep these bytes"}`)
	compressed, err := gzipCompress(jsonBody)
	require.NoError(t, err)
	tests := []struct {
		name        string
		contentType string
		encoding    string
		body        []byte
	}{
		{"json", "application/json", "", jsonBody},
		{"gzip", "application/json", "gzip", compressed},
		{"ndjson", "application/x-ndjson", "", []byte("{\"index\":{}}\n{\"rule\":\"event\"}\n")},
	}
	for _, tt := range tests {
		for _, status := range []int{307, 308} {
			for _, readBody := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/read=%t", tt.name, status, readBody), func(t *testing.T) {
					s, err := NewSender("test", &HTTPConfig{BearerToken: "token"})
					require.NoError(t, err)
					calls := 0
					s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
						calls++
						body, readErr := io.ReadAll(req.Body)
						assert.NoError(t, readErr)
						assert.NoError(t, req.Body.Close())
						assert.Equal(t, tt.body, body)
						assert.Equal(t, http.MethodPost, req.Method)
						assert.Equal(t, tt.contentType, req.Header.Get("Content-Type"))
						assert.Equal(t, tt.encoding, req.Header.Get("Content-Encoding"))
						assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))
						if calls == 1 {
							return redirectResponse(req, status, "/end"), nil
						}
						resp := redirectResponse(req, http.StatusOK, "")
						resp.Body = io.NopCloser(strings.NewReader("ok"))
						return resp, nil
					})
					req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/start", bytes.NewReader(tt.body))
					require.NoError(t, err)
					req.Header.Set("Content-Type", tt.contentType)
					if tt.encoding != "" {
						req.Header.Set("Content-Encoding", tt.encoding)
					}
					if readBody {
						body, sendErr := s.DoReadBody(req.Context(), req)
						require.NoError(t, sendErr)
						assert.Equal(t, "ok", string(body))
					} else {
						require.NoError(t, s.Do(req.Context(), req))
					}
					assert.Equal(t, 2, calls)
				})
			}
		}
	}
}

func TestRedirectNonReplayableBody(t *testing.T) {
	for _, status := range []int{307, 308} {
		for _, mode := range []string{"missing", "failure"} {
			t.Run(fmt.Sprintf("%d/%s", status, mode), func(t *testing.T) {
				s, err := NewSender("test", &HTTPConfig{})
				require.NoError(t, err)
				calls := 0
				s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
					calls++
					assert.NoError(t, req.Body.Close())
					return redirectResponse(req, status, "/end"), nil
				})
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/start", io.NopCloser(strings.NewReader("event")))
				require.NoError(t, err)
				if mode == "failure" {
					req.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("replay failed") }
				}
				require.Error(t, s.Do(req.Context(), req))
				assert.Equal(t, 1, calls)
			})
		}
	}
}

func TestSenderRedirectBodyOnlyDenied(t *testing.T) {
	for _, status := range []int{307, 308} {
		for _, readBody := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/read=%t", status, readBody), func(t *testing.T) {
				s, err := NewSender("test", &HTTPConfig{})
				require.NoError(t, err)
				calls := 0
				s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
					calls++
					assert.Equal(t, "origin.example", req.URL.Host)
					assert.Empty(t, req.Header.Get("Authorization"))
					body, readErr := io.ReadAll(req.Body)
					assert.NoError(t, readErr)
					assert.NoError(t, req.Body.Close())
					assert.Equal(t, "private event", string(body))
					return redirectResponse(req, status, "https://other.example/receive"), nil
				})
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://origin.example/start", strings.NewReader("private event"))
				require.NoError(t, err)
				if readBody {
					_, err = s.DoReadBody(req.Context(), req)
				} else {
					err = s.Do(req.Context(), req)
				}
				var policy *redirectError
				require.ErrorAs(t, err, &policy)
				assert.Equal(t, "cross-origin redirect denied", policy.reason)
				assert.Equal(t, 1, calls)
			})
		}
	}
}

func TestRedirectUserinfo(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		location string
		allowed  bool
	}{
		{"introduced", "https://example.com/start", "https://user:secret@example.com/end", false},
		{"changed password", "https://user:first@example.com/start", "https://user:second@example.com/end", false},
		{"changed user", "https://first:secret@example.com/start", "https://second:secret@example.com/end", false},
		{"same", "https://user:secret@example.com/start", "https://user:secret@example.com/end", true},
		{"relative", "https://user:secret@example.com/start", "/end", true},
		{"removed", "https://user:secret@example.com/start", "https://example.com/end", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := BuildHTTPClient(&HTTPConfig{})
			require.NoError(t, err)
			calls := 0
			client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return redirectResponse(req, http.StatusTemporaryRedirect, tt.location), nil
				}
				return redirectResponse(req, http.StatusOK, ""), nil
			})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tt.origin, http.NoBody)
			require.NoError(t, err)
			resp, err := client.Do(req)
			if tt.allowed {
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				assert.Equal(t, 2, calls)
			} else {
				var denied *redirectError
				require.ErrorAs(t, err, &denied)
				assert.Equal(t, "redirect credentials changed", denied.Error())
				assert.Equal(t, 1, calls)
			}
		})
	}
}

func TestRedirectChainsAndBudget(t *testing.T) {
	tests := []struct {
		name      string
		reason    string
		locations []string
		calls     int
	}{
		{"A to B to A", "cross-origin redirect denied", []string{"https://b.example/end", "https://a.example/end"}, 1},
		{"A to A to B", "cross-origin redirect denied", []string{"/next", "https://b.example/end"}, 2},
		{"loop", "redirect request limit exceeded", []string{"/loop"}, 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := BuildHTTPClient(&HTTPConfig{})
			require.NoError(t, err)
			calls := 0
			client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
				location := tt.locations[min(calls, len(tt.locations)-1)]
				calls++
				return redirectResponse(req, http.StatusTemporaryRedirect, location), nil
			})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://a.example/start", http.NoBody)
			require.NoError(t, err)
			resp, err := client.Do(req)
			if resp != nil {
				require.NoError(t, resp.Body.Close())
			}
			var denied *redirectError
			require.ErrorAs(t, err, &denied)
			assert.Equal(t, tt.reason, denied.reason)
			assert.Equal(t, tt.calls, calls)
		})
	}
}

func TestRedirectReferer(t *testing.T) {
	for _, value := range []string{"", "https://explicit.example/ref"} {
		t.Run(fmt.Sprintf("explicit=%t", value != ""), func(t *testing.T) {
			client, err := BuildHTTPClient(&HTTPConfig{})
			require.NoError(t, err)
			calls := 0
			client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				assert.Equal(t, value, req.Header.Get("Referer"))
				if calls < 3 {
					return redirectResponse(req, http.StatusTemporaryRedirect, "/next?token=other-secret"), nil
				}
				return redirectResponse(req, http.StatusOK, ""), nil
			})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/private-token?token=secret", http.NoBody)
			require.NoError(t, err)
			if value != "" {
				req.Header.Set("Referer", value)
			}
			resp, err := client.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			assert.Equal(t, 3, calls)
		})
	}
}

func TestSenderRedirectHeaderSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("initial-file"), 0o600))
	s, err := NewSender("test", &HTTPConfig{Headers: map[string]ValueSources{
		"X-Mixed": {Values: []string{"same", "public"}, Secrets: []string{"same", "secret"}, Files: []string{path}},
	}})
	require.NoError(t, err)
	s.SetHeader("X-Scope-OrgID", "tenant")
	s.SetBasicAuth("user", "password")
	for _, fileValue := range []string{"initial-file", "rotated-file"} {
		calls := 0
		s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
			calls++
			assert.Equal(t, []string{"same", "public", "same", "secret", fileValue}, req.Header.Values("X-Mixed"))
			assert.Equal(t, []string{"prepared"}, req.Header.Values("X-Other"))
			assert.Equal(t, "tenant", req.Header.Get("X-Scope-OrgID"))
			user, password, ok := req.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, "user", user)
			assert.Equal(t, "password", password)
			if calls == 1 {
				assert.NoError(t, os.WriteFile(path, []byte("rotated-file"), 0o600))
				return redirectResponse(req, http.StatusTemporaryRedirect, "/end"), nil
			}
			return redirectResponse(req, http.StatusOK, ""), nil
		})
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/start", http.NoBody)
		require.NoError(t, err)
		req.Header = http.Header{"X-Other": {"prepared"}, "X-Mixed": {"overridden"}}
		original := req.Header.Clone()
		require.NoError(t, s.Do(req.Context(), req))
		assert.Equal(t, 2, calls)
		assert.Equal(t, original, req.Header)
	}
	for _, deleted := range []bool{false, true} {
		if deleted {
			require.NoError(t, os.Remove(path))
		} else {
			require.NoError(t, os.WriteFile(path, []byte("invalid\r\nvalue"), 0o600))
		}
		s.client.Transport = headerRoundTripper(func(*http.Request) (*http.Response, error) {
			t.Error("invalid header file must fail before any request")
			return nil, errors.New("unexpected delivery")
		})
		require.Error(t, s.HealthCheck(context.Background(), "https://example.com/start"))
	}
}

func TestRedirectConcurrentOrigins(t *testing.T) {
	s, err := NewSender("test", &HTTPConfig{BearerToken: "token"})
	require.NoError(t, err)
	var calls atomic.Int64
	s.client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))
		assert.Equal(t, req.URL.Host, req.Header.Get("X-Target"))
		if req.URL.Path == "/start" {
			return redirectResponse(req, http.StatusTemporaryRedirect, "/end"), nil
		}
		return redirectResponse(req, http.StatusOK, ""), nil
	})
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Go(func() {
			host := fmt.Sprintf("target-%d.example", i)
			req, newErr := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+"/start", http.NoBody)
			if !assert.NoError(t, newErr) {
				return
			}
			req.Header.Set("X-Target", host)
			assert.NoError(t, s.Do(req.Context(), req))
		})
	}
	wg.Wait()
	assert.Equal(t, int64(48), calls.Load())
}

func TestRedirectContextAndTimeout(t *testing.T) {
	for _, canceled := range []bool{true, false} {
		t.Run(fmt.Sprintf("canceled=%t", canceled), func(t *testing.T) {
			client, err := BuildHTTPClient(&HTTPConfig{})
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !canceled {
				client.Timeout = 100 * time.Millisecond
			}
			calls := 0
			client.Transport = headerRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return redirectResponse(req, http.StatusTemporaryRedirect, "/end"), nil
				}
				if canceled {
					cancel()
				}
				<-req.Context().Done()
				return nil, req.Context().Err()
			})
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/start", http.NoBody)
			require.NoError(t, err)
			resp, err := client.Do(req)
			if resp != nil {
				require.NoError(t, resp.Body.Close())
			}
			if canceled {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				var timeout net.Error
				require.ErrorAs(t, err, &timeout)
				assert.True(t, timeout.Timeout())
			}
			assert.Equal(t, 2, calls)
		})
	}
}

func TestRedirectMTLS(t *testing.T) {
	certPath, keyPath := filepath.Join(t.TempDir(), "cert.pem"), filepath.Join(t.TempDir(), "key.pem")
	generateSelfSignedCert(t, certPath, keyPath)
	for _, insecure := range []bool{false, true} {
		t.Run(fmt.Sprintf("insecure=%t", insecure), func(t *testing.T) {
			var deniedConnections, deniedHandshakes, accepted atomic.Int64
			denied := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("denied server received a request")
			}))
			denied.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					deniedConnections.Add(1)
				}
			}
			denied.TLS = &tls.Config{
				MinVersion: tls.VersionTLS12,
				ClientAuth: tls.RequireAnyClientCert,
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					deniedHandshakes.Add(1)
					return nil, nil
				},
			}
			denied.StartTLS()
			defer denied.Close()
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Len(t, req.TLS.PeerCertificates, 1)
				switch req.URL.Path {
				case "/allowed":
					w.Header().Set("Location", "/end")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "/end":
					accepted.Add(1)
					w.WriteHeader(http.StatusOK)
				default:
					w.Header().Set("Location", denied.URL+"/secret")
					w.WriteHeader(http.StatusTemporaryRedirect)
				}
			}))
			origin.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
			origin.StartTLS()
			defer origin.Close()
			s, err := NewSender("test", &HTTPConfig{TLS: TLSClientConfig{
				CertFile: certPath, KeyFile: keyPath, ServerName: "example.com", InsecureSkipVerify: insecure,
			}})
			require.NoError(t, err)
			transport, ok := s.client.Transport.(*http.Transport)
			require.True(t, ok)
			defer transport.CloseIdleConnections()
			transport.TLSClientConfig.RootCAs = x509.NewCertPool()
			transport.TLSClientConfig.RootCAs.AddCert(origin.Certificate())
			require.NoError(t, s.HealthCheck(context.Background(), origin.URL+"/allowed"))
			assert.Equal(t, int64(1), accepted.Load())
			err = s.HealthCheck(context.Background(), origin.URL+"/denied")
			var policy *redirectError
			require.ErrorAs(t, err, &policy)
			assert.Equal(t, "cross-origin redirect denied", policy.reason)
			assert.Zero(t, deniedConnections.Load())
			assert.Zero(t, deniedHandshakes.Load())
		})
	}
}

func TestNormalizeOriginInvalid(t *testing.T) {
	for _, u := range []*url.URL{
		nil,
		{},
		{Scheme: "https", Host: "example.com", Opaque: "secret"},
		{Scheme: "ftp", Host: "example.com"},
		{Scheme: "https", Host: "example.com:0"},
		{Scheme: "https", Host: "example.com:65536"},
		{Scheme: "https", Host: "example.com:invalid"},
		{Scheme: "https", Host: ":443"},
		{Scheme: "https", Host: "bad host"},
		{Scheme: "https", Host: "[example.com]"},
		{Scheme: "https", Host: "[127.0.0.1]"},
		{Scheme: "https", Host: "::1:443"},
	} {
		_, valid := normalizeOrigin(u)
		assert.False(t, valid)
	}
}

func redirectResponse(req *http.Request, status int, location string) *http.Response {
	resp := &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody, Request: req}
	if location != "" {
		resp.Header.Set("Location", location)
	}
	return resp
}

type redirectResponseBody struct {
	closed bool
}

func (*redirectResponseBody) Read([]byte) (int, error) { return 0, io.EOF }

func (b *redirectResponseBody) Close() error {
	b.closed = true
	return nil
}
