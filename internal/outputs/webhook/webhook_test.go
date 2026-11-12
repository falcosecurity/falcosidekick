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

package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestWebhookCommonCases(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "host"},
		{Name: "returns error on server 500", AddressField: "host", MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestWebhookSpecificCases(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{
			Name:         "sends POST by default",
			AddressField: "host",
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				t.Helper()
				assert.Equal(t, http.MethodPost, req.Method)
				assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			},
		},
		{
			Name:         "sends PUT when configured",
			AddressField: "host",
			Config:       map[string]any{"method": "PUT"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				t.Helper()
				assert.Equal(t, http.MethodPut, req.Method)
			},
		},
		{
			Name:         "includes custom headers",
			AddressField: "host",
			Config: map[string]any{
				"headers": map[string]any{
					"X-Custom":      map[string]any{"values": []string{"value", "second"}},
					"Authorization": map[string]any{"secrets": []string{"Bearer token"}},
				},
			},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				t.Helper()
				assert.Equal(t, "value", req.Header.Get("X-Custom"))
				assert.Equal(t, []string{"value", "second"}, req.Header.Values("X-Custom"))
				assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))
			},
		},
		{
			Name:         "returns error on 500",
			AddressField: "host",
			MockStatus:   http.StatusInternalServerError,
			ExpectError:  true,
		},
	})
}

func TestWebhookCreateValidation(t *testing.T) {
	t.Run("healthcheck sends no request", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		o, err := OutputType.New(map[string]any{"host": server.URL}, output.Deps{})
		require.NoError(t, err)
		assert.NoError(t, o.HealthCheck(context.Background()))
		assert.Zero(t, calls.Load(), "a probe would deliver a message to a POST-only endpoint")
	})

	t.Run("healthcheck ignores an unreachable host", func(t *testing.T) {
		o, err := OutputType.New(map[string]any{"host": "http://127.0.0.1:1"}, output.Deps{})
		require.NoError(t, err)
		assert.NoError(t, o.HealthCheck(context.Background()))
	})

	t.Run("send to unreachable host", func(t *testing.T) {
		o, err := OutputType.New(map[string]any{"host": "http://127.0.0.1:1"}, output.Deps{})
		require.NoError(t, err)
		assert.Error(t, o.Send(context.Background(), testutil.CreateValidEvent()))
	})

	t.Run("init and close", func(t *testing.T) {
		o, err := OutputType.New(map[string]any{"host": "http://example.com"}, output.Deps{})
		require.NoError(t, err)
		assert.NoError(t, o.Init(context.Background()))
		assert.NoError(t, o.Close())
	})

	tests := []struct {
		cfg     map[string]any
		name    string
		wantErr bool
	}{
		{
			name:    "missing url",
			cfg:     map[string]any{},
			wantErr: true,
		},
		{
			name: "valid minimal config",
			cfg:  map[string]any{"host": "http://example.com"},
		},
		{
			name: "method defaults to POST",
			cfg:  map[string]any{"host": "http://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := OutputType.New(tt.cfg, output.Deps{})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "webhook", o.Name())
		})
	}
}

func TestWebhookInsecureSkipVerifyDefaults(t *testing.T) {
	o, err := OutputType.New(map[string]any{"host": "http://example.com"}, output.Deps{})
	require.NoError(t, err)

	w := o.(*driver)
	assert.False(t, w.cfg.TLS.InsecureSkipVerify, "InsecureSkipVerify defaults to false")

	o2, err := OutputType.New(map[string]any{"host": "http://example.com", "tls": map[string]any{"insecure_skip_verify": true}}, output.Deps{})
	require.NoError(t, err)
	w2 := o2.(*driver)
	assert.True(t, w2.cfg.TLS.InsecureSkipVerify, "InsecureSkipVerify explicitly true")
}

func TestCreateOutputAcceptsRuntimeOverrides(t *testing.T) {
	d, err := OutputType.New(map[string]any{
		"host": "http://example.com",
		"runtime": map[string]any{
			"minimum_priority": "warning",
			"queue_size":       5000,
			"workers":          4,
			"retry": map[string]any{
				"max_attempts": 5,
			},
			"circuit_breaker": map[string]any{
				"failure_threshold": 10,
			},
			"batching": map[string]any{
				"enabled":    true,
				"batch_size": 1000,
			},
		},
	}, output.Deps{})
	require.NoError(t, err, "runtime override keys must not be rejected")
	assert.Equal(t, "webhook", d.Name())
	pCfg := d.RuntimeConfig()
	assert.Equal(t, 5000, pCfg.QueueSize)
	assert.Equal(t, 4, pCfg.Workers)
	assert.Equal(t, event.PriorityWarning, pCfg.MinPriority)
	require.NotNil(t, pCfg.Retry)
	assert.Equal(t, 5, pCfg.Retry.MaxAttempts)
	require.NotNil(t, pCfg.Batching)
	assert.True(t, pCfg.Batching.IsEnabled())
	assert.Equal(t, 1000, pCfg.Batching.BatchSize)
}

func TestCreateOutputRejectsUnknownKeys(t *testing.T) {
	_, err := OutputType.New(map[string]any{
		"host":  "http://example.com",
		"methd": "PUT",
	}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "methd")
}

func TestCreateOutputInvalidTLSFailsConstruction(t *testing.T) {
	_, err := OutputType.New(map[string]any{
		"host": "https://example.com",
		"tls": map[string]any{
			"ca_file": "/nonexistent/ca.pem",
		},
	}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_file")
}

func TestCreateOutputInvalidClientCertFailsConstruction(t *testing.T) {
	_, err := OutputType.New(map[string]any{
		"host": "https://example.com",
		"tls": map[string]any{
			"cert_file": "/nonexistent/cert.pem",
			"key_file":  "/nonexistent/key.pem",
		},
	}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_file")
}

func TestWebhookHeaderValidation(t *testing.T) {
	tests := []struct {
		cfg  map[string]any
		name string
	}{
		{map[string]any{"headers": map[string]any{"X-Key": "legacy"}}, "legacy flat header"},
		{map[string]any{"headers_file": "/tmp/unsupported"}, "no headers_file"},
		{map[string]any{"headers": map[string]any{"X-Key": map[string]any{"secrets_file": "/tmp/unsupported"}}}, "no nested scalar file resolver"},
		{map[string]any{"headers": map[string]any{"X-Key": map[string]any{"unknown": []string{"value"}}}}, "unknown property"},
		{map[string]any{"headers": map[string]any{
			"X-Key": map[string]any{"secrets": []string{"private-token"}},
			"x-key": map[string]any{"values": []string{"other"}},
		}}, "case duplicate"},
		{map[string]any{"headers": map[string]any{
			"Authorization": map[string]any{"values": []string{"private-token"}},
		}}, "public authorization"},
		{map[string]any{"bearer_token": "private-bearer", "headers": map[string]any{
			"authorization": map[string]any{"secrets": []string{"private-token"}},
		}}, "bearer conflict"},
		{map[string]any{"headers": map[string]any{
			"X-Key": map[string]any{"secrets": []string{"private-token\n"}},
		}}, "invalid value"},
		{map[string]any{"headers": map[string]any{
			"X-Key": map[string]any{"files": []string{filepath.Join(t.TempDir(), "missing")}},
		}}, "missing file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg["host"] = "http://example.com"
			d, err := OutputType.New(tt.cfg, output.Deps{})
			require.Error(t, err)
			assert.Nil(t, d)
			assert.NotContains(t, err.Error(), "private-")
		})
	}
}

func TestWebhookHeaderFileRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorization")
	require.NoError(t, os.WriteFile(path, []byte(" Bearer initial\n"), 0o600))
	captured := make(chan http.Header, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		captured <- req.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d, err := OutputType.New(map[string]any{
		"host": server.URL,
		"HEADERS": map[string]any{
			"authorization": map[string]any{"FILES": []string{path}},
			"X-Key":         map[string]any{"VALUES": []any{"public"}, "SECRETS": []any{"protected"}},
		},
	}, output.Deps{})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, d.Close()) })
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	first := <-captured
	assert.Equal(t, []string{"Bearer initial"}, first.Values("Authorization"))
	assert.Equal(t, []string{"public", "protected"}, first.Values("X-Key"))

	require.NoError(t, os.WriteFile(path, []byte("Bearer rotated\r\n"), 0o600))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	second := <-captured
	assert.Equal(t, []string{"Bearer rotated"}, second.Values("Authorization"))
	assert.Equal(t, []string{"public", "protected"}, second.Values("X-Key"))
}

func TestWebhookRejectsHeaderPropertyAliases(t *testing.T) {
	for _, field := range []string{"values", "secrets", "files"} {
		t.Run(field, func(t *testing.T) {
			_, err := OutputType.New(map[string]any{
				"host": "http://example.com",
				"headers": map[string]any{
					"X-Key": map[string]any{field: []string{}, strings.ToUpper(field): []string{}},
				},
			}, output.Deps{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "duplicate")
		})
	}
}
