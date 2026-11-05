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

package datadog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	testKey    = "dd-s3cret-key-sentinel"
	testAppKey = "dd-s3cret-app-key-sentinel"

	keyEcho = "invalid keys " + testKey + " " + testAppKey
)

func newDriver(t *testing.T, cfg map[string]any) *driver {
	t.Helper()
	d, err := OutputType.New(cfg, output.Deps{})
	require.NoError(t, err)
	return d.(*driver)
}

func TestSchema(t *testing.T) {
	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		fields[f.Name] = f
	}
	assert.True(t, fields["api_key"].Secret)
	assert.True(t, fields["api_key"].Required)
	assert.True(t, fields["app_key"].Secret)
	assert.False(t, fields["app_key"].Required)
	assert.Equal(t, "enum", fields["site"].Type)
	assert.Equal(t, sites, fields["site"].Values)
	assert.Equal(t, defaultSite, fields["site"].Default)
	assert.False(t, fields["host"].Required)
	assert.Nil(t, fields["host"].Default, "site selects the host")
	assert.NotContains(t, fields, "endpoint")
	assert.NotContains(t, fields, "secret_endpoint")
	assert.Contains(t, fields, "runtime.minimum_priority")
}

func TestSiteSelectsHost(t *testing.T) {
	tests := []struct {
		site string
		want string
	}{
		{site: "", want: "https://api.datadoghq.com"},
		{site: "datadoghq.com", want: "https://api.datadoghq.com"},
		{site: "us3.datadoghq.com", want: "https://api.us3.datadoghq.com"},
		{site: "us5.datadoghq.com", want: "https://api.us5.datadoghq.com"},
		{site: "datadoghq.eu", want: "https://api.datadoghq.eu"},
		{site: "ap1.datadoghq.com", want: "https://api.ap1.datadoghq.com"},
		{site: "ap2.datadoghq.com", want: "https://api.ap2.datadoghq.com"},
		{site: "uk1.datadoghq.com", want: "https://api.uk1.datadoghq.com"},
		{site: "ddog-gov.com", want: "https://api.ddog-gov.com"},
		{site: "us2.ddog-gov.com", want: "https://api.us2.ddog-gov.com"},
		{site: "DatadogHQ.EU", want: "https://api.datadoghq.eu"},
	}
	for _, tt := range tests {
		t.Run(tt.site, func(t *testing.T) {
			cfg := map[string]any{"api_key": testKey}
			if tt.site != "" {
				cfg["site"] = tt.site
			}
			d := newDriver(t, cfg)
			assert.Equal(t, tt.want, d.cfg.Host)
			assert.Equal(t, strings.Replace(tt.want, "https://api.", "https://event-management-intake.", 1), d.cfg.intakeHost)
		})
	}

	t.Run("host overrides every site host", func(t *testing.T) {
		d := newDriver(t, map[string]any{"api_key": testKey, "site": "datadoghq.eu", "host": "https://proxy.example"})
		assert.Equal(t, "https://proxy.example", d.cfg.Host)
		assert.Equal(t, "https://proxy.example", d.cfg.intakeHost)
	})
}

func TestValidation(t *testing.T) {
	tests := []struct {
		cfg  map[string]any
		name string
		want string
	}{
		{name: "missing api_key", cfg: map[string]any{}, want: "api_key: is required"},
		{name: "blank api_key", cfg: map[string]any{"api_key": "  "}, want: "api_key: is required"},
		{name: "api_key with newline", cfg: map[string]any{"api_key": testKey + "\n"}, want: "api_key: invalid header value"},
		{name: "unknown site", cfg: map[string]any{"api_key": testKey, "site": "datadoghq.cn"}, want: "site: must be one of"},
		{name: "endpoint", cfg: map[string]any{"api_key": testKey, "endpoint": "/x"}, want: "endpoint: is not supported"},
		{name: "secret_endpoint", cfg: map[string]any{"api_key": testKey, "secret_endpoint": "/x"}, want: "secret_endpoint: is not supported"},
		{name: "invalid host", cfg: map[string]any{"api_key": testKey, "host": "ftp://h"}, want: "host: scheme must be http or https"},
		{name: "api_key query param", cfg: map[string]any{
			"api_key": testKey, "query_params": map[string]any{"api_key": map[string]any{"secrets": []string{testKey}}},
		}, want: `query_params["api_key"]: is set by the output`},
		{name: "api key header", cfg: map[string]any{
			"api_key": testKey, "headers": map[string]any{"dd-api-key": map[string]any{"secrets": []string{"other"}}},
		}, want: "api_key: cannot be combined with a DD-API-KEY header"},
		{name: "unknown key", cfg: map[string]any{"api_key": testKey, "apikey": testKey}, want: "unknown keys: apikey"},
		{name: "blank app_key", cfg: map[string]any{"api_key": testKey, "app_key": " "}, want: "app_key: is required"},
		{name: "app_key with newline", cfg: map[string]any{"api_key": testKey, "app_key": testAppKey + "\r\n"}, want: "app_key: invalid header value"},
		{name: "app key header", cfg: map[string]any{
			"api_key": testKey, "app_key": testAppKey,
			"headers": map[string]any{"DD-Application-Key": map[string]any{"secrets": []string{testAppKey}}},
		}, want: "app_key: cannot be combined with a DD-APPLICATION-KEY header"},
		{name: "bearer and password", cfg: map[string]any{"api_key": testKey, "bearer_token": "b", "password": "p"}, want: "bearer_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := OutputType.New(tt.cfg, output.Deps{})
			require.Error(t, err)
			assert.Nil(t, d)
			assert.Contains(t, err.Error(), tt.want)
			assert.Contains(t, err.Error(), "datadog")
			assert.NotContains(t, err.Error(), testKey)
			assert.NotContains(t, err.Error(), testAppKey)
		})
	}
}

func TestInvalidTLSFailsConstruction(t *testing.T) {
	_, err := OutputType.New(map[string]any{"api_key": testKey, "tls": map[string]any{"ca_file": "/nonexistent/ca.pem"}}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_file")
}

func TestRuntimeOverrides(t *testing.T) {
	d := newDriver(t, map[string]any{"api_key": testKey, "runtime": map[string]any{"minimum_priority": "error", "workers": 3}})
	assert.Equal(t, event.PriorityError, d.RuntimeConfig().MinPriority)
	assert.Equal(t, 3, d.RuntimeConfig().Workers)
	assert.Equal(t, "datadog", d.Name())
	assert.NoError(t, d.Init(context.Background()))
	assert.NoError(t, d.Close())
}

func TestSendPostsEvent(t *testing.T) {
	rec, server := testutil.NewRecorder(t, http.StatusAccepted, "")
	d := newDriver(t, map[string]any{
		"api_key": testKey, "host": server.URL, "base_path": "/proxy",
		"headers": map[string]any{"X-Extra": map[string]any{"values": []string{"yes"}}},
	})

	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))

	reqs := rec.Received()
	require.Len(t, reqs, 1)
	got := reqs[0]
	assert.Equal(t, http.MethodPost, got.Method)
	assert.Equal(t, "/proxy/api/v1/events", got.URL.Path)
	assert.Empty(t, got.URL.RawQuery, "the key is never sent in the URL")
	assert.Equal(t, testKey, got.Header.Get("DD-API-KEY"))
	assert.Empty(t, got.Header.Values("DD-APPLICATION-KEY"), "v1 needs only the API key")
	assert.Equal(t, "application/json", got.Header.Get("Content-Type"))
	assert.Equal(t, "yes", got.Header.Get("X-Extra"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(got.Body, &body))
	assert.Equal(t, map[string]any{
		"title":            "Write below binary dir",
		"text":             "File below a known binary directory opened for writing",
		"alert_type":       "error",
		"source_type_name": "falco",
		"tags": []any{
			"fd.name:/bin/hack", "proc.cmdline:touch /bin/hack", "user.name:root",
			"source:syscall", "source:falco", "hostname:node-1", "filesystem", "mitre_persistence",
		},
	}, body)
}

func TestSendAcceptsAny2xx(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusAccepted} {
		_, server := testutil.NewRecorder(t, status, "")
		d := newDriver(t, map[string]any{"api_key": testKey, "host": server.URL})
		assert.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	}
}

func TestSendErrorsNeverExposeKey(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			_, server := testutil.NewRecorder(t, status, keyEcho)
			d := newDriver(t, map[string]any{"api_key": testKey, "host": server.URL})
			err := d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "datadog response: HTTP")
			assert.NotContains(t, err.Error(), testKey)
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		d := newDriver(t, map[string]any{"api_key": testKey, "host": "http://127.0.0.1:1"})
		err := d.Send(context.Background(), testutil.CreateValidEvent())
		require.Error(t, err)
		assert.NotContains(t, err.Error(), testKey)
	})
}

func TestHealthCheck(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		wantErr       bool
		misconfigured bool
	}{
		{name: "valid key", status: http.StatusOK},
		{name: "invalid key", status: http.StatusForbidden, wantErr: true, misconfigured: true},
		{name: "unauthorized", status: http.StatusUnauthorized, wantErr: true, misconfigured: true},
		{name: "wrong path", status: http.StatusNotFound, wantErr: true, misconfigured: true},
		{name: "rate limited", status: http.StatusTooManyRequests, wantErr: true},
		{name: "server error", status: http.StatusServiceUnavailable, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, server := testutil.NewRecorder(t, tt.status, keyEcho)
			d := newDriver(t, map[string]any{"api_key": testKey, "host": server.URL})

			err := d.HealthCheck(context.Background())

			reqs := rec.Received()
			require.Len(t, reqs, 1)
			assert.Equal(t, http.MethodGet, reqs[0].Method)
			assert.Equal(t, "/api/v1/validate", reqs[0].URL.Path)
			assert.Equal(t, testKey, reqs[0].Header.Get("DD-API-KEY"))
			assert.Empty(t, reqs[0].Body, "the probe posts no event")
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.misconfigured, errors.Is(err, output.ErrMisconfigured))
			assert.NotContains(t, err.Error(), testKey)
		})
	}

	t.Run("unreachable is transient", func(t *testing.T) {
		d := newDriver(t, map[string]any{"api_key": testKey, "host": "http://127.0.0.1:1"})
		err := d.HealthCheck(context.Background())
		require.Error(t, err)
		assert.NotErrorIs(t, err, output.ErrMisconfigured)
	})
}

func TestNewPayload(t *testing.T) {
	t.Run("alert type", func(t *testing.T) {
		tests := map[event.Priority]string{
			event.PriorityEmergency:     "error",
			event.PriorityAlert:         "error",
			event.PriorityCritical:      "error",
			event.PriorityError:         "error",
			event.PriorityWarning:       "warning",
			event.PriorityNotice:        "info",
			event.PriorityInformational: "info",
			event.PriorityDebug:         "info",
		}
		for priority, want := range tests {
			evt := testutil.CreateValidEvent()
			evt.Priority = priority
			assert.Equal(t, want, newPayload(evt).AlertType, priority)
		}
	})

	t.Run("without hostname and tags", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.Hostname, evt.Tags = "", nil
		evt.OutputFields = map[string]any{"b": 2, "a": "x"}
		assert.Equal(t, []string{"a:x", "b:2", "source:syscall", "source:falco"}, newPayload(evt).Tags)
	})

	t.Run("does not reorder the event tags", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.Tags = []string{"z", "a"}
		newPayload(evt)
		assert.Equal(t, []string{"z", "a"}, evt.Tags)
	})

	t.Run("text is truncated to the API limit", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.Output = strings.Repeat("é", maxTextRunes+10)
		text := newPayload(evt).Text
		assert.Equal(t, maxTextRunes, len([]rune(text)))
		assert.True(t, strings.HasSuffix(text, "..."))
	})
}

func TestModeSelection(t *testing.T) {
	tests := []struct {
		cfg        map[string]any
		name       string
		wantPath   string
		wantAppKey string
	}{
		{name: "api key only sends v1", cfg: map[string]any{}, wantPath: "/api/v1/events"},
		{name: "empty app key sends v1", cfg: map[string]any{"app_key": ""}, wantPath: "/api/v1/events"},
		{name: "app key sends v2", cfg: map[string]any{"app_key": testAppKey}, wantPath: "/api/v2/events", wantAppKey: testAppKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, server := testutil.NewRecorder(t, http.StatusAccepted, "")
			tt.cfg["api_key"], tt.cfg["host"] = testKey, server.URL
			d := newDriver(t, tt.cfg)

			require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))

			reqs := rec.Received()
			require.Len(t, reqs, 1)
			assert.Equal(t, tt.wantPath, reqs[0].URL.Path)
			assert.Equal(t, testKey, reqs[0].Header.Get("DD-API-KEY"))
			assert.Equal(t, tt.wantAppKey, reqs[0].Header.Get("DD-APPLICATION-KEY"))
		})
	}

	t.Run("v2 uses the intake host of the site", func(t *testing.T) {
		d := newDriver(t, map[string]any{"api_key": testKey, "app_key": testAppKey, "site": "datadoghq.eu"})
		assert.True(t, d.v2())
		assert.Equal(t, "https://event-management-intake.datadoghq.eu", d.cfg.intakeHost)
		assert.Equal(t, "https://api.datadoghq.eu", d.cfg.Host, "key validation stays on the API host")
	})
}

func TestSendV2PostsAlertEvent(t *testing.T) {
	rec, server := testutil.NewRecorder(t, http.StatusAccepted, "")
	d := newDriver(t, map[string]any{"api_key": testKey, "app_key": testAppKey, "host": server.URL, "base_path": "/dd"})

	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))

	reqs := rec.Received()
	require.Len(t, reqs, 1)
	got := reqs[0]
	assert.Equal(t, http.MethodPost, got.Method)
	assert.Equal(t, "/dd/api/v2/events", got.URL.Path)
	assert.Empty(t, got.URL.RawQuery)
	assert.Equal(t, "application/json", got.Header.Get("Content-Type"))
	var body map[string]any
	require.NoError(t, json.Unmarshal(got.Body, &body))
	assert.Equal(t, map[string]any{"data": map[string]any{
		"type": "event",
		"attributes": map[string]any{
			"title":           "Write below binary dir",
			"message":         "File below a known binary directory opened for writing",
			"category":        "alert",
			"aggregation_key": "test-uuid-001",
			"timestamp":       "2026-04-01T10:30:00Z",
			"tags": []any{
				"fd.name:/bin/hack", "proc.cmdline:touch /bin/hack", "user.name:root",
				"source:syscall", "source:falco", "hostname:node-1", "filesystem", "mitre_persistence",
			},
			"attributes": map[string]any{"status": "error", "priority": "3"},
		},
	}}, body)
}

func TestSendV2ErrorsNeverExposeKeys(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests} {
		_, server := testutil.NewRecorder(t, status, keyEcho)
		d := newDriver(t, map[string]any{"api_key": testKey, "app_key": testAppKey, "host": server.URL})
		err := d.Send(context.Background(), testutil.CreateValidEvent())
		require.Error(t, err)
		assert.NotContains(t, err.Error(), testKey)
		assert.NotContains(t, err.Error(), testAppKey)
	}
}

func TestHealthCheckV2ValidatesBothKeys(t *testing.T) {
	tests := []struct {
		name          string
		wantPaths     []string
		validate      int
		validateKeys  int
		wantErr       bool
		misconfigured bool
	}{
		{name: "both valid", validate: 200, validateKeys: 200, wantPaths: []string{validateRoute, validateKeysRoute}},
		{name: "api key rejected", validate: 403, validateKeys: 200, wantPaths: []string{validateRoute}, wantErr: true, misconfigured: true},
		{name: "app key unauthorized", validate: 200, validateKeys: 401, wantPaths: []string{validateRoute, validateKeysRoute}, wantErr: true, misconfigured: true},
		{name: "app key forbidden", validate: 200, validateKeys: 403, wantPaths: []string{validateRoute, validateKeysRoute}, wantErr: true, misconfigured: true},
		{name: "rate limited", validate: 200, validateKeys: 429, wantPaths: []string{validateRoute, validateKeysRoute}, wantErr: true},
		{name: "server error", validate: 502, validateKeys: 200, wantPaths: []string{validateRoute}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, server := testutil.NewRecorder(t, http.StatusOK, keyEcho)
			rec.StatusByPath = map[string]int{validateRoute: tt.validate, validateKeysRoute: tt.validateKeys}
			d := newDriver(t, map[string]any{"api_key": testKey, "app_key": testAppKey, "host": server.URL})

			err := d.HealthCheck(context.Background())

			reqs := rec.Received()
			paths := make([]string, 0, len(reqs))
			for _, r := range reqs {
				paths = append(paths, r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, testKey, r.Header.Get("DD-API-KEY"))
				assert.Equal(t, testAppKey, r.Header.Get("DD-APPLICATION-KEY"))
			}
			assert.Equal(t, tt.wantPaths, paths, "no event is posted")
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.misconfigured, errors.Is(err, output.ErrMisconfigured))
			assert.NotContains(t, err.Error(), testKey)
			assert.NotContains(t, err.Error(), testAppKey)
		})
	}
}

func TestNewV2Payload(t *testing.T) {
	t.Run("status and priority", func(t *testing.T) {
		tests := map[event.Priority][2]string{
			event.PriorityEmergency:     {"error", "1"},
			event.PriorityAlert:         {"error", "1"},
			event.PriorityCritical:      {"error", "2"},
			event.PriorityError:         {"error", "3"},
			event.PriorityWarning:       {"warn", "4"},
			event.PriorityNotice:        {"ok", "5"},
			event.PriorityInformational: {"ok", "5"},
			event.PriorityDebug:         {"ok", "5"},
		}
		for priority, want := range tests {
			evt := testutil.CreateValidEvent()
			evt.Priority = priority
			alert := newV2Payload(evt).Data.Attributes.Attributes
			assert.Equal(t, want[0], alert.Status, priority)
			assert.Equal(t, want[1], alert.Priority, priority)
		}
	})

	t.Run("schema limits", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.Rule = strings.Repeat("r", maxTitleRunes+1)
		evt.Output = ""
		evt.OutputFields = map[string]any{}
		for i := range maxTags + 20 {
			evt.OutputFields[fmt.Sprintf("field%03d", i)] = strings.Repeat("v", maxTagRunes)
		}
		payload := newV2Payload(evt)
		attrs := payload.Data.Attributes
		assert.Len(t, []rune(attrs.Title), maxTitleRunes)
		body, err := json.Marshal(payload)
		require.NoError(t, err)
		assert.NotContains(t, string(body), `"message"`, "an empty message is omitted")
		assert.Len(t, attrs.Tags, maxTags)
		for _, tag := range attrs.Tags {
			assert.LessOrEqual(t, len([]rune(tag)), maxTagRunes)
		}
	})

	t.Run("event without uuid has no aggregation key", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.UUID = ""
		body, err := json.Marshal(newV2Payload(evt))
		require.NoError(t, err)
		assert.NotContains(t, string(body), "aggregation_key")
		assert.NotContains(t, string(body), `"message":""`)
	})
}
