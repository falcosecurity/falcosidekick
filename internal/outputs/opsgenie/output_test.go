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

package opsgenie

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const testKey = "0psg3n1e-s3cret-sentinel"

func schemaField(t *testing.T, fieldName string) output.SchemaField {
	t.Helper()
	for _, f := range OutputType.Schema.Fields {
		if f.Name == fieldName {
			return f
		}
	}
	t.Fatalf("schema has no field %q", fieldName)
	return output.SchemaField{}
}

func TestSchema(t *testing.T) {
	key := schemaField(t, "api_key")
	assert.True(t, key.Secret)
	assert.True(t, key.Required)

	region := schemaField(t, "region")
	assert.Equal(t, "enum", region.Type)
	assert.Equal(t, []string{"us", "eu"}, region.Values)
	assert.Equal(t, "us", region.Default)

	host := schemaField(t, "host")
	assert.False(t, host.Required)
	assert.Nil(t, host.Default, "region selects the default host")

	for _, f := range OutputType.Schema.Fields {
		assert.NotEqual(t, "endpoint", f.Name, "the driver owns the route")
		assert.NotEqual(t, "secret_endpoint", f.Name, "the driver owns the route")
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		raw      map[string]any
		name     string
		wantErr  string
		wantHost string
	}{
		{name: "us default", raw: map[string]any{"api_key": testKey}, wantHost: hostUS},
		{name: "eu", raw: map[string]any{"api_key": testKey, "region": "eu"}, wantHost: hostEU},
		{name: "eu upper case from v2", raw: map[string]any{"api_key": testKey, "region": "EU"}, wantHost: hostEU},
		{name: "host overrides region", raw: map[string]any{"api_key": testKey, "region": "eu", "host": "https://proxy.example"}, wantHost: "https://proxy.example"},
		{name: "unknown region", raw: map[string]any{"api_key": testKey, "region": "ap"}, wantErr: `region: must be us/eu, got "ap"`},
		{name: "missing api key", raw: map[string]any{}, wantErr: "api_key: is required"},
		{name: "invalid header value", raw: map[string]any{"api_key": testKey + "\n"}, wantErr: "api_key: invalid header value"},
		{name: "basic auth conflict", raw: map[string]any{"api_key": testKey, "username": "u", "password": "p"}, wantErr: "cannot combine api_key with basic auth"},
		{name: "bearer conflict", raw: map[string]any{"api_key": testKey, "bearer_token": "t"}, wantErr: "cannot combine api_key with basic auth or bearer_token"},
		{name: "authorization header conflict", raw: map[string]any{"api_key": testKey, "headers": map[string]any{"authorization": map[string]any{"values": []string{"x"}}}}, wantErr: "cannot combine api_key with an authorization header"},
		{name: "endpoint rejected", raw: map[string]any{"api_key": testKey, "endpoint": "/x"}, wantErr: "endpoint: is not supported"},
		{name: "invalid host", raw: map[string]any{"api_key": testKey, "host": "api.opsgenie.com"}, wantErr: "host: must include scheme and host"},
		{name: "v2 key name", raw: map[string]any{"apikey": testKey}, wantErr: "unknown keys"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := OutputType.New(tc.raw, output.Deps{})
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.NotContains(t, err.Error(), testKey)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantHost, d.(*driver).cfg.Host)
			assert.Equal(t, name, d.Name())
		})
	}
}

func TestPriorityMapping(t *testing.T) {
	for p, want := range map[event.Priority]string{
		event.PriorityEmergency:     "P1",
		event.PriorityAlert:         "P1",
		event.PriorityCritical:      "P2",
		event.PriorityError:         "P3",
		event.PriorityWarning:       "P4",
		event.PriorityNotice:        "P5",
		event.PriorityInformational: "P5",
		event.PriorityDebug:         "P5",
	} {
		t.Run(string(p), func(t *testing.T) {
			assert.Equal(t, want, priority(p))
		})
	}
}

// Mirrors the v2 TestNewOpsgeniePayload expectations, plus alias and tags.
func TestBuildAlertV2Parity(t *testing.T) {
	evt := &event.Event{
		Time:         time.Date(2001, 1, 1, 1, 10, 0, 0, time.UTC),
		Output:       "This is a test from falcosidekick",
		Rule:         "Test rule",
		Source:       "syscalls",
		Hostname:     "test-host",
		Priority:     event.PriorityDebug,
		Tags:         []string{"test", "example"},
		OutputFields: map[string]any{"proc.name": "falcosidekick", "proc.tty": float64(1234), "user.uid": nil},
	}
	got := buildAlert(evt)
	assert.Equal(t, alert{
		Message:     "This is a test from falcosidekick",
		Entity:      "Falcosidekick",
		Description: "Test rule",
		Details: map[string]string{
			"hostname":  "test-host",
			"priority":  "Debug",
			"tags":      "test, example",
			"proc_name": "falcosidekick",
			"proc_tty":  "1234",
			"rule":      "Test rule",
			"source":    "syscalls",
		},
		Priority: "P5",
		Tags:     []string{"test", "example"},
	}, got)
}

func TestBuildAlertLimits(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Output = strings.Repeat("ö", 200)
	evt.Tags = []string{""}
	for range 25 {
		evt.Tags = append(evt.Tags, strings.Repeat("t", 60))
	}
	got := buildAlert(evt)
	assert.Len(t, []rune(got.Message), maxMessageRunes)
	assert.True(t, strings.HasSuffix(got.Message, "..."))
	assert.Equal(t, "test-uuid-001", got.Alias)
	require.Len(t, got.Tags, maxTags)
	for _, tag := range got.Tags {
		assert.Len(t, tag, maxTagRunes)
	}

	evt.Output = ""
	evt.UUID = strings.Repeat("u", maxAliasLen+1)
	evt.Tags = nil
	got = buildAlert(evt)
	assert.Equal(t, evt.Rule, got.Message)
	assert.Empty(t, got.Alias)
	assert.Nil(t, got.Tags)
}

func TestBuildDetailsBudget(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.OutputFields = map[string]any{
		"a.small":      "kept",
		"b.cmdline":    strings.Repeat("x", 9000),
		"c.after":      "left out",
		"proc.pid":     42,
		"ignored.nil":  nil,
		"z.never.seen": "z",
	}
	details := buildDetails(evt)

	total := 0
	for key, value := range details {
		total += utf8.RuneCountInString(key) + utf8.RuneCountInString(value)
	}
	assert.LessOrEqual(t, total, maxDetailsRunes)
	assert.Equal(t, evt.Rule, details["rule"], "metadata comes first")
	assert.Equal(t, evt.Hostname, details["hostname"])
	assert.Equal(t, "kept", details["a_small"])
	assert.True(t, strings.HasSuffix(details["b_cmdline"], "..."), "the field crossing the budget is truncated")
	assert.NotContains(t, details, "c_after", "fields after the budget are left out")
	assert.NotContains(t, details, "ignored_nil")
}

func TestSendDelivers(t *testing.T) {
	rec, server := testutil.NewRecorder(t, http.StatusAccepted, `{"result":"Request will be processed","took":0.3,"requestId":"r"}`)
	d, err := OutputType.New(map[string]any{"api_key": testKey, "host": server.URL, "base_path": "/proxy"}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.Init(context.Background()))

	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	reqs := rec.Received()
	require.Len(t, reqs, 1)
	c := reqs[0]
	assert.Equal(t, http.MethodPost, c.Method)
	assert.Equal(t, "/proxy/v2/alerts", c.URL.Path)
	assert.Equal(t, "GenieKey "+testKey, c.Header.Get("Authorization"))
	assert.Equal(t, "application/json", c.Header.Get("Content-Type"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(c.Body, &body))
	assert.Equal(t, "P3", body["priority"])
	assert.Equal(t, "Falcosidekick", body["entity"])
	assert.Equal(t, "test-uuid-001", body["alias"])
	assert.Equal(t, "Write below binary dir", body["description"])
	assert.NotContains(t, string(c.Body), testKey)
	assert.NoError(t, d.Close())
}

func TestSendErrorsAreSafe(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusUnprocessableEntity, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			_, server := testutil.NewRecorder(t, status, `{"message":"bad key `+testKey+`"}`)
			d, err := OutputType.New(map[string]any{"api_key": testKey, "host": server.URL}, output.Deps{})
			require.NoError(t, err)
			err = d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "opsgenie response")
			assert.Equal(t, status, shared.HTTPStatus(err))
			assert.NotContains(t, err.Error(), testKey)
		})
	}
}

func TestSendTargetErrorIsSafe(t *testing.T) {
	d, err := OutputType.New(map[string]any{"api_key": testKey}, output.Deps{})
	require.NoError(t, err)
	drv := d.(*driver)
	drv.cfg.QueryParams = map[string]shared.ValueSources{"t": {Files: []string{t.TempDir() + "/missing"}}}
	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opsgenie target")
	err = d.HealthCheck(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "opsgenie target")
}

func TestSendHonorsContext(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	d, err := OutputType.New(map[string]any{"api_key": testKey, "host": server.URL}, output.Deps{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = d.Send(ctx, testutil.CreateValidEvent())
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestHealthCheck(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		misconfigured bool
	}{
		{name: "ok", status: http.StatusOK},
		{name: "invalid key or disabled integration", status: http.StatusUnauthorized, misconfigured: true},
		{name: "wrong base path", status: http.StatusNotFound, misconfigured: true},
		{name: "key without configuration access", status: http.StatusForbidden},
		{name: "plan does not allow", status: http.StatusPaymentRequired},
		{name: "throttled", status: http.StatusTooManyRequests},
		{name: "unavailable", status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, server := testutil.NewRecorder(t, tc.status, `{"message":"`+testKey+`"}`)
			d, err := OutputType.New(map[string]any{"api_key": testKey, "host": server.URL, "base_path": "/og"}, output.Deps{})
			require.NoError(t, err)

			err = d.HealthCheck(context.Background())
			reqs := rec.Received()
			require.Len(t, reqs, 1)
			assert.Equal(t, http.MethodGet, reqs[0].Method)
			assert.Equal(t, "/og/v2/heartbeats", reqs[0].URL.Path)
			assert.Equal(t, "GenieKey "+testKey, reqs[0].Header.Get("Authorization"))
			if tc.status == http.StatusOK {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.misconfigured, errors.Is(err, output.ErrMisconfigured))
			assert.NotContains(t, err.Error(), testKey)
		})
	}
}

func TestRuntimeConfig(t *testing.T) {
	d, err := OutputType.New(map[string]any{"api_key": testKey, "runtime": map[string]any{"workers": 2}}, output.Deps{})
	require.NoError(t, err)
	assert.Equal(t, 2, d.RuntimeConfig().Workers)
}
