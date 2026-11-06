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

package pagerduty

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const testKey = "R0UT1NGKEYs3cretSentinel00000000"

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
	key := schemaField(t, "routing_key")
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
		{name: "us default", raw: map[string]any{"routing_key": testKey}, wantHost: hostUS},
		{name: "us explicit", raw: map[string]any{"routing_key": testKey, "region": "us"}, wantHost: hostUS},
		{name: "eu", raw: map[string]any{"routing_key": testKey, "region": "eu"}, wantHost: hostEU},
		{name: "eu upper case from v2", raw: map[string]any{"routing_key": testKey, "region": "EU"}, wantHost: hostEU},
		{name: "host overrides region", raw: map[string]any{"routing_key": testKey, "region": "eu", "host": "https://proxy.example:8443"}, wantHost: "https://proxy.example:8443"},
		{name: "unknown region", raw: map[string]any{"routing_key": testKey, "region": "ap"}, wantErr: `region: must be us/eu`},
		{name: "missing routing key", raw: map[string]any{}, wantErr: "routing_key: is required"},
		{name: "blank routing key", raw: map[string]any{"routing_key": "  "}, wantErr: "routing_key: is required"},
		{name: "endpoint rejected", raw: map[string]any{"routing_key": testKey, "endpoint": "/x"}, wantErr: "endpoint: is not supported"},
		{name: "secret endpoint rejected", raw: map[string]any{"routing_key": testKey, "secret_endpoint": "/x"}, wantErr: "secret_endpoint: is not supported"},
		{name: "invalid host", raw: map[string]any{"routing_key": testKey, "host": "ftp://x"}, wantErr: "host: scheme must be http or https"},
		{name: "unknown key", raw: map[string]any{"routing_key": testKey, "minimum_priority": "error"}, wantErr: "unknown keys"},
		{name: "v2 key name", raw: map[string]any{"routingkey": testKey}, wantErr: "unknown keys"},
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

func TestSeverityMapping(t *testing.T) {
	for p, want := range map[event.Priority]string{
		event.PriorityEmergency:     "critical",
		event.PriorityAlert:         "critical",
		event.PriorityCritical:      "critical",
		event.PriorityError:         "error",
		event.PriorityWarning:       "warning",
		event.PriorityNotice:        "info",
		event.PriorityInformational: "info",
		event.PriorityDebug:         "info",
	} {
		t.Run(string(p), func(t *testing.T) {
			assert.Equal(t, want, severity(p))
		})
	}
}

func TestBuildEvent(t *testing.T) {
	evt := testutil.CreateValidEvent()
	got := buildEvent(evt, testKey)

	assert.Equal(t, testKey, got.RoutingKey)
	assert.Equal(t, "trigger", got.EventAction)
	assert.Equal(t, "test-uuid-001", got.DedupKey)
	assert.Equal(t, evt.Output, got.Payload.Summary)
	assert.Equal(t, "node-1", got.Payload.Source)
	assert.Equal(t, "error", got.Payload.Severity)
	assert.Equal(t, "2026-04-01T10:30:00Z", got.Payload.Timestamp)
	details := got.Payload.CustomDetails
	assert.Equal(t, "/bin/hack", details["fd.name"])
	assert.Equal(t, "Write below binary dir", details["rule"])
	assert.Equal(t, "Error", details["priority"])
	assert.Equal(t, "syscall", details["source"])
	assert.Equal(t, "node-1", details["hostname"])
	assert.Equal(t, "filesystem, mitre_persistence", details["tags"])
	_, mutated := evt.OutputFields["hostname"]
	assert.False(t, mutated, "the event must not be modified")
}

func TestBuildEventFallbacksAndLimits(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Output = ""
	evt.Hostname = ""
	evt.Tags = nil
	evt.UUID = strings.Repeat("u", maxDedupKeyLen+1)
	got := buildEvent(evt, testKey)
	assert.Equal(t, evt.Rule, got.Payload.Summary)
	assert.Equal(t, "falco", got.Payload.Source)
	assert.Empty(t, got.DedupKey, "an over-long key is left to PagerDuty")
	assert.NotContains(t, got.Payload.CustomDetails, "hostname")
	assert.NotContains(t, got.Payload.CustomDetails, "tags")

	evt.Output = strings.Repeat("é", maxSummaryRunes+10)
	got = buildEvent(evt, testKey)
	assert.Len(t, []rune(got.Payload.Summary), maxSummaryRunes)
	assert.True(t, strings.HasSuffix(got.Payload.Summary, "..."))
}

func TestSendDelivers(t *testing.T) {
	rec, server := testutil.NewRecorder(t, http.StatusAccepted, `{"status":"success","message":"Event processed","dedup_key":"test-uuid-001"}`)
	d, err := OutputType.New(map[string]any{"routing_key": testKey, "host": server.URL, "base_path": "/proxy"}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.Init(context.Background()))

	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	reqs := rec.Received()
	require.Len(t, reqs, 1)
	c := reqs[0]
	assert.Equal(t, http.MethodPost, c.Method)
	assert.Equal(t, "/proxy/v2/enqueue", c.URL.Path)
	assert.Equal(t, "application/json", c.Header.Get("Content-Type"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(c.Body, &body))
	assert.Equal(t, testKey, body["routing_key"])
	assert.Equal(t, "trigger", body["event_action"])
	assert.Equal(t, "test-uuid-001", body["dedup_key"])
	payload := body["payload"].(map[string]any)
	assert.Equal(t, "error", payload["severity"])
	assert.Equal(t, "node-1", payload["source"])
	assert.Contains(t, payload, "custom_details")
	assert.NoError(t, d.Close())
}

func TestSendErrorsAreSafe(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			_, server := testutil.NewRecorder(t, status, `{"status":"invalid event","message":"`+testKey+`"}`)
			d, err := OutputType.New(map[string]any{"routing_key": testKey, "host": server.URL}, output.Deps{})
			require.NoError(t, err)
			err = d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "pagerduty response")
			assert.NotContains(t, err.Error(), testKey)
		})
	}
}

func TestSendUnreachableIsSafe(t *testing.T) {
	_, server := testutil.NewRecorder(t, http.StatusAccepted, "")
	server.Close()
	d, err := OutputType.New(map[string]any{"routing_key": testKey, "host": server.URL}, output.Deps{})
	require.NoError(t, err)
	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), testKey)
}

func TestSendTargetErrorIsSafe(t *testing.T) {
	missing := t.TempDir() + "/missing"
	d, err := OutputType.New(map[string]any{"routing_key": testKey}, output.Deps{})
	require.NoError(t, err)
	drv := d.(*driver)
	drv.cfg.QueryParams = map[string]shared.ValueSources{"t": {Files: []string{missing}}}
	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pagerduty target")
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
	d, err := OutputType.New(map[string]any{"routing_key": testKey, "host": server.URL}, output.Deps{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = d.Send(ctx, testutil.CreateValidEvent())
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestHealthCheckIsNoOp(t *testing.T) {
	rec, server := testutil.NewRecorder(t, http.StatusUnauthorized, "")
	d, err := OutputType.New(map[string]any{"routing_key": testKey, "host": server.URL}, output.Deps{})
	require.NoError(t, err)
	assert.NoError(t, d.HealthCheck(context.Background()))
	assert.Empty(t, rec.Received(), "a probe would open an alert")
}

func TestRuntimeConfig(t *testing.T) {
	d, err := OutputType.New(map[string]any{"routing_key": testKey, "runtime": map[string]any{"workers": 3}}, output.Deps{})
	require.NoError(t, err)
	assert.Equal(t, 3, d.RuntimeConfig().Workers)
}
