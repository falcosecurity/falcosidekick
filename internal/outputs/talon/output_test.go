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

package talon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const secretEcho = "unknown hook /hook/PATH_SECRET with token BEARER_SECRET"

func TestCreateValidation(t *testing.T) {
	tests := []struct {
		cfg  map[string]any
		name string
		want string
	}{
		{name: "valid", cfg: map[string]any{"host": "http://falco-talon:2803"}},
		{name: "valid https with endpoint", cfg: map[string]any{"host": "https://talon.example.com", "endpoint": "/falco"}},
		{name: "valid secret endpoint", cfg: map[string]any{"host": "https://talon.example.com", "secret_endpoint": "/hook/token"}},
		{name: "missing host", cfg: map[string]any{}, want: "host: is required"},
		{name: "host with path", cfg: map[string]any{"host": "http://falco-talon:2803/"}, want: "host:"},
		{name: "invalid endpoint", cfg: map[string]any{"host": "http://falco-talon:2803", "endpoint": "falco"}, want: "endpoint: must be a valid path"},
		{name: "endpoint and secret endpoint", cfg: map[string]any{
			"host": "http://falco-talon:2803", "endpoint": "/a", "secret_endpoint": "/b",
		}, want: "endpoint: cannot be combined with secret_endpoint"},
		{name: "legacy address key", cfg: map[string]any{"address": "http://falco-talon:2803"}, want: "address"},
		{name: "legacy checkcert key", cfg: map[string]any{"host": "http://falco-talon:2803", "checkcert": false}, want: "checkcert"},
		{name: "minimum_priority outside runtime", cfg: map[string]any{
			"host": "http://falco-talon:2803", "minimum_priority": "warning",
		}, want: "minimum_priority"},
		{name: "missing ca file", cfg: map[string]any{
			"host": "https://talon.example.com", "tls": map[string]any{"ca_file": "/nonexistent/ca.pem"},
		}, want: "ca_file"},
		{name: "missing client cert", cfg: map[string]any{
			"host": "https://talon.example.com", "tls": map[string]any{"cert_file": "/nonexistent/c.pem", "key_file": "/nonexistent/k.pem"},
		}, want: "cert_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := OutputType.New(tt.cfg, output.Deps{})
			if tt.want == "" {
				require.NoError(t, err)
				assert.Equal(t, name, d.Name())
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Contains(t, err.Error(), name)
			assert.Nil(t, d)
		})
	}
}

func TestDefaults(t *testing.T) {
	d, err := OutputType.New(map[string]any{"host": "http://falco-talon:2803"}, output.Deps{})
	require.NoError(t, err)
	cfg := d.(*driver).cfg
	assert.Equal(t, "/", cfg.Endpoint)
	assert.False(t, cfg.TLS.InsecureSkipVerify)
}

func TestSchema(t *testing.T) {
	assert.Equal(t, "talon", OutputType.Name)
	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		_, dup := fields[f.Name]
		assert.False(t, dup, "duplicate schema field %s", f.Name)
		fields[f.Name] = f
	}
	assert.True(t, fields["host"].Required)
	assert.Equal(t, "/", fields["endpoint"].Default)
	assert.True(t, fields["secret_endpoint"].Secret)
	assert.False(t, fields["secret_endpoint"].Required)
	assert.True(t, fields["password"].Secret)
	assert.True(t, fields["bearer_token"].Secret)
	assert.Contains(t, fields, "tls.insecure_skip_verify")
	assert.Contains(t, fields, "runtime.minimum_priority")
}

func TestBuildPayload(t *testing.T) {
	evt := testutil.CreateValidEvent()
	raw, err := json.Marshal(buildPayload(evt))
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"time": "2026-04-01T10:30:00Z",
		"uuid": "test-uuid-001",
		"output": "File below a known binary directory opened for writing",
		"priority": "Error",
		"rule": "Write below binary dir",
		"source": "syscall",
		"hostname": "node-1",
		"tags": ["filesystem", "mitre_persistence"],
		"output_fields": {"fd.name": "/bin/hack", "proc.cmdline": "touch /bin/hack", "user.name": "root"}
	}`, string(raw))
}

func TestBuildPayloadOmitsEmptyOptionalFields(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Hostname, evt.UUID, evt.Tags = "", "", nil
	raw, err := json.Marshal(buildPayload(evt))
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.NotContains(t, got, "hostname")
	assert.NotContains(t, got, "uuid")
	assert.NotContains(t, got, "tags")
	assert.Contains(t, got, "output_fields")
}

func TestBuildPayloadPriorityIsTitleCased(t *testing.T) {
	for p, want := range map[event.Priority]string{
		event.PriorityDebug: "Debug", event.PriorityInformational: "Informational", event.PriorityNotice: "Notice",
		event.PriorityWarning: "Warning", event.PriorityError: "Error", event.PriorityCritical: "Critical",
		event.PriorityAlert: "Alert", event.PriorityEmergency: "Emergency",
	} {
		evt := testutil.CreateValidEvent()
		evt.Priority = p
		assert.Equal(t, want, buildPayload(evt).Priority)
	}
}

func TestSendDelivers(t *testing.T) {
	tests := []struct {
		cfg      map[string]any
		name     string
		wantPath string
	}{
		{name: "default endpoint", cfg: map[string]any{}, wantPath: "/"},
		{name: "base path and endpoint", cfg: map[string]any{"base_path": "/talon", "endpoint": "/events"}, wantPath: "/talon/events"},
		{name: "secret endpoint", cfg: map[string]any{"secret_endpoint": "/hook/PATH_SECRET"}, wantPath: "/hook/PATH_SECRET"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, requests := testutil.StartCaptureServer(t, http.StatusOK, "")
			tt.cfg["host"] = server.URL
			tt.cfg["headers"] = map[string]any{"X-Custom": map[string]any{"values": []string{"falco"}}}
			d, err := OutputType.New(tt.cfg, output.Deps{})
			require.NoError(t, err)
			require.NoError(t, d.Init(context.Background()))
			t.Cleanup(func() { assert.NoError(t, d.Close()) })

			require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
			req := <-requests
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, tt.wantPath, req.URL.Path)
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, "falco", req.Header.Get("X-Custom"))
			var got map[string]any
			require.NoError(t, json.Unmarshal(req.Body, &got))
			assert.Equal(t, "Write below binary dir", got["rule"])
			assert.Equal(t, "Error", got["priority"])
			assert.Equal(t, "/bin/hack", got["output_fields"].(map[string]any)["fd.name"])
		})
	}
}

func TestSendErrorsAreSafe(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, requests := testutil.StartCaptureServer(t, status, secretEcho)
			d, err := OutputType.New(map[string]any{
				"host":            server.URL,
				"secret_endpoint": "/hook/PATH_SECRET",
				"bearer_token":    "BEARER_SECRET",
			}, output.Deps{})
			require.NoError(t, err)
			err = d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			<-requests
			assert.Equal(t, status, shared.HTTPStatus(err))
			assert.NotContains(t, err.Error(), "PATH_SECRET")
			assert.NotContains(t, err.Error(), "BEARER_SECRET")
			var diagnostic *shared.DeliveryError
			assert.ErrorAs(t, err, &diagnostic)
		})
	}
}

func TestSendUnreachable(t *testing.T) {
	d, err := OutputType.New(map[string]any{"host": "http://127.0.0.1:1"}, output.Deps{})
	require.NoError(t, err)
	assert.Error(t, d.Send(context.Background(), testutil.CreateValidEvent()))
}

func TestHealthCheck(t *testing.T) {
	tests := []struct {
		name          string
		basePath      string
		wantPath      string
		status        int
		wantErr       bool
		misconfigured bool
	}{
		{name: "healthy", status: http.StatusOK, wantPath: "/healthz"},
		{name: "healthy under base path", basePath: "/talon", status: http.StatusOK, wantPath: "/talon/healthz"},
		{name: "unknown path", status: http.StatusNotFound, wantPath: "/healthz", wantErr: true, misconfigured: true},
		{name: "rejected credentials", status: http.StatusUnauthorized, wantPath: "/healthz", wantErr: true, misconfigured: true},
		{name: "forbidden", status: http.StatusForbidden, wantPath: "/healthz", wantErr: true, misconfigured: true},
		{name: "unavailable", status: http.StatusServiceUnavailable, wantPath: "/healthz", wantErr: true},
		{name: "server error", status: http.StatusInternalServerError, wantPath: "/healthz", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, requests := testutil.StartCaptureServer(t, tt.status, secretEcho)
			cfg := map[string]any{"host": server.URL, "secret_endpoint": "/hook/PATH_SECRET"}
			if tt.basePath != "" {
				cfg["base_path"] = tt.basePath
			}
			d, err := OutputType.New(cfg, output.Deps{})
			require.NoError(t, err)
			err = d.HealthCheck(context.Background())
			req := <-requests
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, tt.wantPath, req.URL.Path)
			assert.Empty(t, req.Body)
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.misconfigured, errors.Is(err, output.ErrMisconfigured))
			assert.NotContains(t, err.Error(), "PATH_SECRET")
		})
	}
}

func TestHealthCheckUnreachableIsTransient(t *testing.T) {
	d, err := OutputType.New(map[string]any{"host": "http://127.0.0.1:1"}, output.Deps{})
	require.NoError(t, err)
	err = d.HealthCheck(context.Background())
	require.Error(t, err)
	assert.NotErrorIs(t, err, output.ErrMisconfigured)
}

func TestHealthCheckUntrustedCertificateIsMisconfigured(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	d, err := OutputType.New(map[string]any{"host": server.URL}, output.Deps{})
	require.NoError(t, err)
	assert.ErrorIs(t, d.HealthCheck(context.Background()), output.ErrMisconfigured)

	skip, err := OutputType.New(map[string]any{"host": server.URL, "tls": map[string]any{"insecure_skip_verify": true}}, output.Deps{})
	require.NoError(t, err)
	assert.NoError(t, skip.HealthCheck(context.Background()))
}

func TestRuntimeOverrides(t *testing.T) {
	d, err := OutputType.New(map[string]any{
		"host":    "http://falco-talon:2803",
		"runtime": map[string]any{"minimum_priority": "notice", "queue_size": 50},
	}, output.Deps{})
	require.NoError(t, err)
	rc := d.RuntimeConfig()
	assert.Equal(t, event.PriorityNotice, rc.MinPriority)
	assert.Equal(t, 50, rc.QueueSize)
}

func TestConstructorErrorsNameFieldWithoutValue(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	for _, host := range []string{"https://u:" + sentinel + "@ho st", "ftp://u:" + sentinel + "@host"} {
		_, err := OutputType.New(map[string]any{"host": host}, output.Deps{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "host:")
		assert.NotContains(t, err.Error(), sentinel)
	}
}
