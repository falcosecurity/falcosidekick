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
	"time"

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

// keys returns a config holding both keys plus the given settings.
func keys(extra map[string]any) map[string]any {
	cfg := map[string]any{"api_key": testKey, "app_key": testAppKey}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

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
	assert.True(t, fields["app_key"].Required, "Events API v2 needs the application key")
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
			cfg := keys(nil)
			if tt.site != "" {
				cfg["site"] = tt.site
			}
			d := newDriver(t, cfg)
			assert.Equal(t, tt.want, d.cfg.Host, "key validation stays on the API host")
			assert.Equal(t, strings.Replace(tt.want, "https://api.", "https://event-management-intake.", 1), d.cfg.intakeHost)
		})
	}

	t.Run("host overrides every site host", func(t *testing.T) {
		d := newDriver(t, keys(map[string]any{"site": "datadoghq.eu", "host": "https://proxy.example"}))
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
		{name: "missing api_key", cfg: map[string]any{"app_key": testAppKey}, want: "api_key: is required"},
		{name: "blank api_key", cfg: map[string]any{"api_key": "  ", "app_key": testAppKey}, want: "api_key: is required"},
		{name: "api_key with newline", cfg: keys(map[string]any{"api_key": testKey + "\n"}), want: "api_key: invalid header value"},
		{name: "missing app_key", cfg: map[string]any{"api_key": testKey}, want: "app_key: is required"},
		{name: "blank app_key", cfg: keys(map[string]any{"app_key": " "}), want: "app_key: is required"},
		{name: "app_key with newline", cfg: keys(map[string]any{"app_key": testAppKey + "\r\n"}), want: "app_key: invalid header value"},
		{name: "unknown site", cfg: keys(map[string]any{"site": "datadoghq.cn"}), want: "site: must be one of"},
		{name: "endpoint", cfg: keys(map[string]any{"endpoint": "/x"}), want: "endpoint: is not supported"},
		{name: "secret_endpoint", cfg: keys(map[string]any{"secret_endpoint": "/x"}), want: "secret_endpoint: is not supported"},
		{name: "invalid host", cfg: keys(map[string]any{"host": "ftp://h"}), want: "host: scheme must be http or https"},
		{name: "api_key query param", cfg: keys(map[string]any{
			"query_params": map[string]any{"api_key": map[string]any{"secrets": []string{testKey}}},
		}), want: `query_params["api_key"]: is set by the output`},
		{name: "api key header", cfg: keys(map[string]any{
			"headers": map[string]any{"dd-api-key": map[string]any{"secrets": []string{"other"}}},
		}), want: "api_key: cannot be combined with a DD-API-KEY header"},
		{name: "app key header", cfg: keys(map[string]any{
			"headers": map[string]any{"DD-Application-Key": map[string]any{"secrets": []string{testAppKey}}},
		}), want: "app_key: cannot be combined with a DD-APPLICATION-KEY header"},
		{name: "unknown key", cfg: keys(map[string]any{"apikey": testKey}), want: "unknown keys: apikey"},
		{name: "bearer and password", cfg: keys(map[string]any{"bearer_token": "b", "password": "p"}), want: "bearer_token"},
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
	_, err := OutputType.New(keys(map[string]any{"tls": map[string]any{"ca_file": "/nonexistent/ca.pem"}}), output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_file")
}

func TestRuntimeOverrides(t *testing.T) {
	d := newDriver(t, keys(map[string]any{"runtime": map[string]any{"minimum_priority": "error", "workers": 3}}))
	assert.Equal(t, event.PriorityError, d.RuntimeConfig().MinPriority)
	assert.Equal(t, 3, d.RuntimeConfig().Workers)
	assert.Equal(t, "datadog", d.Name())
	assert.NoError(t, d.Init(context.Background()))
	assert.NoError(t, d.Close())
}

func TestSendPostsAlertEvent(t *testing.T) {
	rec, server := testutil.NewRecorder(t, http.StatusAccepted, "")
	d := newDriver(t, keys(map[string]any{
		"host": server.URL, "base_path": "/dd",
		"headers": map[string]any{"X-Extra": map[string]any{"values": []string{"yes"}}},
	}))

	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))

	reqs := rec.Received()
	require.Len(t, reqs, 1)
	got := reqs[0]
	assert.Equal(t, http.MethodPost, got.Method)
	assert.Equal(t, "/dd/api/v2/events", got.URL.Path)
	assert.Empty(t, got.URL.RawQuery, "the keys are never sent in the URL")
	assert.Equal(t, testKey, got.Header.Get("DD-API-KEY"))
	assert.Equal(t, testAppKey, got.Header.Get("DD-APPLICATION-KEY"))
	assert.Equal(t, "application/json", got.Header.Get("Content-Type"))
	assert.Equal(t, "yes", got.Header.Get("X-Extra"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(got.Body, &body))
	assert.Equal(t, map[string]any{"data": map[string]any{
		"type": "event",
		"attributes": map[string]any{
			"title":           "Write below binary dir",
			"message":         "File below a known binary directory opened for writing",
			"category":        "alert",
			"aggregation_key": "test-uuid-001",
			"host":            "node-1",
			"timestamp":       "2026-04-01T10:30:00Z",
			"tags":            []any{"falco_source:syscall", "filesystem", "mitre_persistence"},
			"attributes": map[string]any{
				"status":   "error",
				"priority": "3",
				"custom": map[string]any{"output_fields": map[string]any{
					"fd.name": "/bin/hack", "proc.cmdline": "touch /bin/hack", "user.name": "root",
				}},
			},
		},
	}}, body)
}

func TestEventsAndProbeUseTheirOwnHosts(t *testing.T) {
	apiRec, apiServer := testutil.NewRecorder(t, http.StatusOK, "")
	intakeRec, intakeServer := testutil.NewRecorder(t, http.StatusAccepted, "")
	d := newDriver(t, keys(map[string]any{"site": "datadoghq.eu"}))
	assert.Equal(t, "https://event-management-intake.datadoghq.eu", d.cfg.intakeHost)
	assert.Equal(t, "https://api.datadoghq.eu", d.cfg.Host)
	d.cfg.Host, d.cfg.intakeHost = apiServer.URL, intakeServer.URL

	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	require.NoError(t, d.HealthCheck(context.Background()))

	require.Len(t, intakeRec.Received(), 1)
	assert.Equal(t, "/api/v2/events", intakeRec.Received()[0].URL.Path)
	require.Len(t, apiRec.Received(), 1)
	assert.Equal(t, "/api/v2/validate_keys", apiRec.Received()[0].URL.Path)
}

func TestSendAcceptsAny2xx(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusAccepted} {
		_, server := testutil.NewRecorder(t, status, "")
		d := newDriver(t, keys(map[string]any{"host": server.URL}))
		assert.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	}
}

func TestSendErrorsNeverExposeKeys(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			_, server := testutil.NewRecorder(t, status, keyEcho)
			d := newDriver(t, keys(map[string]any{"host": server.URL}))
			err := d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "datadog response: HTTP")
			assert.NotContains(t, err.Error(), testKey)
			assert.NotContains(t, err.Error(), testAppKey)
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		d := newDriver(t, keys(map[string]any{"host": "http://127.0.0.1:1"}))
		err := d.Send(context.Background(), testutil.CreateValidEvent())
		require.Error(t, err)
		assert.NotContains(t, err.Error(), testKey)
		assert.NotContains(t, err.Error(), testAppKey)
	})
}

func TestHealthCheckValidatesBothKeys(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		wantErr       bool
		misconfigured bool
	}{
		{name: "valid keys", status: http.StatusOK},
		{name: "unauthorized", status: http.StatusUnauthorized, wantErr: true, misconfigured: true},
		{name: "forbidden", status: http.StatusForbidden, wantErr: true, misconfigured: true},
		{name: "wrong path", status: http.StatusNotFound, wantErr: true, misconfigured: true},
		{name: "rate limited", status: http.StatusTooManyRequests, wantErr: true},
		{name: "server error", status: http.StatusServiceUnavailable, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, server := testutil.NewRecorder(t, tt.status, keyEcho)
			d := newDriver(t, keys(map[string]any{"host": server.URL}))

			err := d.HealthCheck(context.Background())

			reqs := rec.Received()
			require.Len(t, reqs, 1, "one probe validates both keys")
			assert.Equal(t, http.MethodGet, reqs[0].Method)
			assert.Equal(t, "/api/v2/validate_keys", reqs[0].URL.Path)
			assert.Equal(t, testKey, reqs[0].Header.Get("DD-API-KEY"))
			assert.Equal(t, testAppKey, reqs[0].Header.Get("DD-APPLICATION-KEY"))
			assert.Empty(t, reqs[0].Body, "the probe posts no event")
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

	t.Run("unreachable is transient", func(t *testing.T) {
		d := newDriver(t, keys(map[string]any{"host": "http://127.0.0.1:1"}))
		err := d.HealthCheck(context.Background())
		require.Error(t, err)
		assert.NotErrorIs(t, err, output.ErrMisconfigured)
	})
}

func TestNewPayload(t *testing.T) {
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
			alert := newPayload(evt).Data.Attributes.Attributes
			assert.Equal(t, want[0], alert.Status, priority)
			assert.Equal(t, want[1], alert.Priority, priority)
		}
	})

	t.Run("tags carry no reserved source tag and no output fields", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.Source = "k8s_audit"
		evt.Tags = []string{"z", "a"}
		tags := newPayload(evt).Data.Attributes.Tags
		assert.Equal(t, []string{"falco_source:k8s_audit", "a", "z"}, tags)
		assert.Equal(t, []string{"z", "a"}, evt.Tags, "the event tags are not reordered")
	})

	t.Run("without hostname, tags and output fields", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.Hostname, evt.Tags, evt.OutputFields = "", nil, map[string]any{}
		body, err := json.Marshal(newPayload(evt))
		require.NoError(t, err)
		assert.NotContains(t, string(body), `"host"`)
		assert.NotContains(t, string(body), `"custom"`)
		assert.Contains(t, string(body), `"tags":["falco_source:syscall"]`)
	})

	t.Run("timestamp is the event time", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.Time = evt.Time.Add(1500 * time.Millisecond)
		assert.Equal(t, "2026-04-01T10:30:01.5Z", newPayload(evt).Data.Attributes.Timestamp)
	})

	t.Run("schema limits", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.Rule = strings.Repeat("r", maxTitleRunes+1)
		evt.Output = strings.Repeat("é", maxMessageRunes+10)
		evt.UUID = strings.Repeat("u", maxKeyRunes+1)
		evt.Tags = nil
		// One more than the limit with the source tag.
		for i := range maxTags {
			evt.Tags = append(evt.Tags, fmt.Sprintf("tag%03d", i)+strings.Repeat("v", maxTagRunes))
		}
		attrs := newPayload(evt).Data.Attributes
		assert.Len(t, []rune(attrs.Title), maxTitleRunes)
		assert.Len(t, []rune(attrs.Message), maxMessageRunes)
		assert.True(t, strings.HasSuffix(attrs.Message, "..."))
		assert.Len(t, []rune(attrs.AggregationKey), maxKeyRunes)
		assert.Len(t, attrs.Tags, maxTags)
		assert.Equal(t, "falco_source:syscall", attrs.Tags[0], "the source tag survives the cap")
		for _, tag := range attrs.Tags {
			assert.LessOrEqual(t, len([]rune(tag)), maxTagRunes)
		}
	})

	t.Run("event without uuid or output omits them", func(t *testing.T) {
		evt := testutil.CreateValidEvent()
		evt.UUID, evt.Output = "", ""
		body, err := json.Marshal(newPayload(evt))
		require.NoError(t, err)
		assert.NotContains(t, string(body), "aggregation_key")
		assert.NotContains(t, string(body), `"message"`)
	})
}
