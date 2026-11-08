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

package grafanaoncall

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	testToken    = "m12xmIjOcgwH74UF8CN4dk0Dh"
	testEndpoint = "/integrations/v1/formatted_webhook/" + testToken + "/"
)

// startServer reflects the token in its body to prove errors never echo it.
func startServer(t *testing.T, status int) (server *httptest.Server, received <-chan testutil.CapturedRequest) {
	t.Helper()
	return testutil.StartCaptureServer(t, status, "response body "+testToken)
}

func TestCreateValidation(t *testing.T) {
	tests := []struct {
		cfg  map[string]any
		name string
		want string
	}{
		{name: "valid", cfg: map[string]any{"host": "https://oncall.example.com", "secret_endpoint": testEndpoint}},
		{name: "valid with base path", cfg: map[string]any{"host": "https://example.com", "base_path": "/oncall", "secret_endpoint": testEndpoint}},
		{name: "missing host", cfg: map[string]any{"secret_endpoint": testEndpoint}, want: "host: is required"},
		{name: "missing secret_endpoint", cfg: map[string]any{"host": "https://oncall.example.com"}, want: "secret_endpoint: is required"},
		{name: "public endpoint rejected", cfg: map[string]any{
			"host": "https://oncall.example.com", "endpoint": testEndpoint,
		}, want: "endpoint: is not supported; use secret_endpoint"},
		{name: "host with path rejected", cfg: map[string]any{
			"host": "https://oncall.example.com" + testEndpoint, "secret_endpoint": testEndpoint,
		}, want: "host:"},
		{name: "invalid secret_endpoint", cfg: map[string]any{
			"host": "https://oncall.example.com", "secret_endpoint": "integrations/" + testToken,
		}, want: "secret_endpoint: must be a valid path"},
		{name: "unknown key", cfg: map[string]any{
			"host": "https://oncall.example.com", "secret_endpoint": testEndpoint, "webhookurl": "x",
		}, want: "webhookurl"},
		{name: "legacy customheaders key", cfg: map[string]any{
			"host": "https://oncall.example.com", "secret_endpoint": testEndpoint, "customheaders": map[string]any{"X": "y"},
		}, want: "customheaders"},
		{name: "minimum_priority outside runtime", cfg: map[string]any{
			"host": "https://oncall.example.com", "secret_endpoint": testEndpoint, "minimum_priority": "warning",
		}, want: "minimum_priority"},
		{name: "bearer and basic auth", cfg: map[string]any{
			"host": "https://oncall.example.com", "secret_endpoint": testEndpoint, "bearer_token": "glsa_x", "password": "p",
		}, want: "bearer_token"},
		{name: "missing ca file", cfg: map[string]any{
			"host": "https://oncall.example.com", "secret_endpoint": testEndpoint, "tls": map[string]any{"ca_file": "/nonexistent/ca.pem"},
		}, want: "ca_file"},
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
			assert.NotContains(t, err.Error(), testToken)
			assert.Nil(t, d)
		})
	}
}

func TestSchema(t *testing.T) {
	assert.Equal(t, "grafanaoncall", OutputType.Name)
	assert.Equal(t, output.CategoryAlerting, OutputType.Category)
	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		_, dup := fields[f.Name]
		assert.False(t, dup, "duplicate schema field %s", f.Name)
		fields[f.Name] = f
	}
	require.Contains(t, fields, "host")
	assert.True(t, fields["host"].Required)
	assert.Empty(t, fields["host"].Default)
	require.Contains(t, fields, "secret_endpoint")
	assert.True(t, fields["secret_endpoint"].Secret)
	assert.True(t, fields["secret_endpoint"].Required)
	assert.NotContains(t, fields, "endpoint")
	assert.True(t, fields["password"].Secret)
	assert.True(t, fields["bearer_token"].Secret)
	require.Contains(t, fields, "headers")
	for _, entry := range fields["headers"].EntryFields {
		assert.Equal(t, entry.Name == "secrets", entry.Secret, entry.Name)
	}
	assert.Contains(t, fields, "tls.ca_file")
	assert.Contains(t, fields, "runtime.minimum_priority")
}

func TestBuildPayload(t *testing.T) {
	evt := testutil.CreateValidEvent()
	got := buildPayload(evt)
	assert.Equal(t, payload{
		AlertUID: "test-uuid-001",
		State:    "alerting",
		Title:    "[Error] Write below binary dir",
		Message:  "File below a known binary directory opened for writing",
	}, got)

	raw, err := json.Marshal(got)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"alert_uid": "test-uuid-001",
		"state": "alerting",
		"title": "[Error] Write below binary dir",
		"message": "File below a known binary directory opened for writing"
	}`, string(raw))
}

func TestBuildPayloadTitlePerPriority(t *testing.T) {
	for _, p := range []event.Priority{
		event.PriorityDebug, event.PriorityInformational, event.PriorityNotice, event.PriorityWarning,
		event.PriorityError, event.PriorityCritical, event.PriorityAlert, event.PriorityEmergency,
	} {
		t.Run(string(p), func(t *testing.T) {
			evt := testutil.CreateValidEvent()
			evt.Priority = p
			assert.Equal(t, "["+p.String()+"] "+evt.Rule, buildPayload(evt).Title)
		})
	}
}

func TestSendDelivers(t *testing.T) {
	server, requests := startServer(t, http.StatusOK)
	d, err := OutputType.New(map[string]any{
		"host":            server.URL,
		"secret_endpoint": testEndpoint,
		"bearer_token":    "glsa_token",
		"headers": map[string]any{
			"X-Custom": map[string]any{"values": []string{"falco"}},
		},
	}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.Init(context.Background()))
	t.Cleanup(func() { assert.NoError(t, d.Close()) })

	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	req := <-requests
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, testEndpoint, req.URL.Path)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "Bearer glsa_token", req.Header.Get("Authorization"))
	assert.Equal(t, "falco", req.Header.Get("X-Custom"))
	var got map[string]any
	require.NoError(t, json.Unmarshal(req.Body, &got))
	assert.Equal(t, map[string]any{
		"alert_uid": "test-uuid-001",
		"state":     "alerting",
		"title":     "[Error] Write below binary dir",
		"message":   "File below a known binary directory opened for writing",
	}, got)
}

func TestSendWithBasePathAndQuery(t *testing.T) {
	server, requests := startServer(t, http.StatusOK)
	d, err := OutputType.New(map[string]any{
		"host":            server.URL,
		"base_path":       "/oncall/",
		"secret_endpoint": testEndpoint,
	}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Equal(t, "/oncall"+testEndpoint, (<-requests).URL.Path)
}

func TestSendErrorsAreSafe(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound,
		http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, requests := startServer(t, status)
			d, err := OutputType.New(map[string]any{
				"host":            server.URL,
				"secret_endpoint": testEndpoint,
				"bearer_token":    "glsa_BEARER_SECRET",
				"query_params":    map[string]any{"token": map[string]any{"secrets": []string{"QUERY_SECRET"}}},
			}, output.Deps{})
			require.NoError(t, err)

			err = d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			<-requests
			assert.Contains(t, err.Error(), http.StatusText(status))
			assert.Equal(t, status, shared.HTTPStatus(err))
			for _, secret := range []string{testToken, "BEARER_SECRET", "QUERY_SECRET"} {
				assert.NotContains(t, err.Error(), secret)
			}
			var diagnostic *shared.DeliveryError
			assert.ErrorAs(t, err, &diagnostic)
		})
	}
}

func TestSendUnreachable(t *testing.T) {
	d, err := OutputType.New(map[string]any{"host": "http://127.0.0.1:1", "secret_endpoint": testEndpoint}, output.Deps{})
	require.NoError(t, err)
	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), testToken)
}

func TestHealthCheckSendsNoRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d, err := OutputType.New(map[string]any{"host": server.URL, "secret_endpoint": testEndpoint}, output.Deps{})
	require.NoError(t, err)
	assert.NoError(t, d.HealthCheck(context.Background()))
	assert.Zero(t, calls.Load(), "a probe would create an alert")

	unreachable, err := OutputType.New(map[string]any{"host": "http://127.0.0.1:1", "secret_endpoint": testEndpoint}, output.Deps{})
	require.NoError(t, err)
	assert.NoError(t, unreachable.HealthCheck(context.Background()))
}

func TestRuntimeOverrides(t *testing.T) {
	d, err := OutputType.New(map[string]any{
		"host":            "https://oncall.example.com",
		"secret_endpoint": testEndpoint,
		"runtime": map[string]any{
			"minimum_priority": "critical",
			"workers":          2,
		},
	}, output.Deps{})
	require.NoError(t, err)
	rc := d.RuntimeConfig()
	assert.Equal(t, event.PriorityCritical, rc.MinPriority)
	assert.Equal(t, 2, rc.Workers)
}

func TestTLSDefaults(t *testing.T) {
	d, err := OutputType.New(map[string]any{"host": "https://oncall.example.com", "secret_endpoint": testEndpoint}, output.Deps{})
	require.NoError(t, err)
	assert.False(t, d.(*driver).cfg.TLS.InsecureSkipVerify)
}

func TestConstructorErrorsNeverExposeURL(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "malformed", value: "https://oncall.example.com:bad/" + sentinel, want: "host: invalid URL"},
		{name: "missing scheme", value: "oncall.example.com/" + sentinel, want: "host: must include scheme and host"},
		{name: "unsupported scheme", value: "ftp://oncall.example.com/" + sentinel, want: "host: scheme must be http or https"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := OutputType.New(map[string]any{"host": tc.value, "secret_endpoint": "/x/" + sentinel}, output.Deps{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), sentinel)
		})
	}
}
