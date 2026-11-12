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

//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	datadogAPIKey = "e2eDatadogApiKey0123456789abcdef"
	datadogAppKey = "e2eDatadogAppKey0123456789abcdef0123456"
)

// datadogRequest mirrors the Events API v2 alert EventCreateRequestPayload:
// https://github.com/DataDog/datadog-api-client-go/blob/master/.generator/schemas/v2/openapi.yaml
type datadogRequest struct {
	Data struct {
		Type       string `json:"type"`
		Attributes struct {
			Attributes struct {
				Custom   map[string]any   `json:"custom"`
				Status   string           `json:"status"`
				Priority string           `json:"priority"`
				Links    []map[string]any `json:"links"`
			} `json:"attributes"`
			AggregationKey string   `json:"aggregation_key"`
			Category       string   `json:"category"`
			Host           string   `json:"host"`
			IntegrationID  string   `json:"integration_id"`
			Message        string   `json:"message"`
			Timestamp      string   `json:"timestamp"`
			Title          string   `json:"title"`
			Tags           []string `json:"tags"`
		} `json:"attributes"`
	} `json:"data"`
}

// datadogAPI is a strict fake of Events API v2 that answers 403 to wrong keys, as Datadog does.
// It knows no v1 route.
type datadogAPI struct {
	events      []datadogRequest
	rejected    []string
	keyChecks   int
	eventStatus int
	mu          sync.Mutex
}

func (d *datadogAPI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	reject := func(status int, reason string) {
		d.rejected = append(d.rejected, req.Method+" "+req.URL.Path+": "+reason)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"errors":["`+http.StatusText(status)+`"]}`)
	}
	if req.URL.Query().Has("api_key") {
		reject(http.StatusBadRequest, "key in the query string")
		return
	}
	if req.Header.Get("DD-API-KEY") != datadogAPIKey {
		reject(http.StatusForbidden, "wrong key")
		return
	}
	if req.Header.Get("DD-APPLICATION-KEY") != datadogAppKey {
		reject(http.StatusForbidden, "wrong application key")
		return
	}
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/api/v2/validate_keys":
		d.keyChecks++
		w.Header().Set("Content-Type", contentTypeJSON)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	case req.Method == http.MethodPost && req.URL.Path == "/api/v2/events":
		d.postEvent(w, req, reject)
	default:
		reject(http.StatusNotFound, "unknown route")
	}
}

func (d *datadogAPI) postEvent(w http.ResponseWriter, req *http.Request, reject func(int, string)) {
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusBadRequest, "content type "+req.Header.Get("Content-Type"))
		return
	}
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	var body datadogRequest
	if err := dec.Decode(&body); err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	attrs := body.Data.Attributes
	switch {
	case dec.More():
		reject(http.StatusBadRequest, "trailing data")
	case body.Data.Type != "event":
		reject(http.StatusBadRequest, "data.type "+body.Data.Type)
	case attrs.Category != "alert":
		reject(http.StatusBadRequest, "category "+attrs.Category)
	case attrs.Title == "" || len([]rune(attrs.Title)) > 500:
		reject(http.StatusBadRequest, "title length")
	case len([]rune(attrs.Message)) > 4000:
		reject(http.StatusBadRequest, "message length")
	case len([]rune(attrs.AggregationKey)) > 100:
		reject(http.StatusBadRequest, "aggregation_key length")
	case len(attrs.Tags) == 0 || len(attrs.Tags) > 100:
		reject(http.StatusBadRequest, "tag count")
	case slices.ContainsFunc(attrs.Tags, func(tag string) bool { return len([]rune(tag)) > 200 || strings.HasPrefix(tag, "source:") }):
		reject(http.StatusBadRequest, "tag too long or reserved")
	case !slices.Contains([]string{"warn", "error", "ok"}, attrs.Attributes.Status):
		reject(http.StatusBadRequest, "status "+attrs.Attributes.Status)
	case attrs.Attributes.Priority != "" && !slices.Contains([]string{"1", "2", "3", "4", "5"}, attrs.Attributes.Priority):
		reject(http.StatusBadRequest, "priority "+attrs.Attributes.Priority)
	default:
		if attrs.Timestamp != "" {
			ts, err := time.Parse(time.RFC3339Nano, attrs.Timestamp)
			if err != nil || time.Since(ts) > 18*time.Hour {
				reject(http.StatusBadRequest, "timestamp is not ISO 8601 or older than 18h")
				return
			}
		}
		d.events = append(d.events, body)
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(d.eventStatus)
		_, _ = io.WriteString(w, `{"data":{"type":"event","attributes":{"attributes":{"evt":{"uid":"e2e"}}}}}`)
	}
}

func (d *datadogAPI) snapshot() (events []datadogRequest, rejected []string, keyChecks int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]datadogRequest(nil), d.events...), append([]string(nil), d.rejected...), d.keyChecks
}

func datadogConfig(host, apiKey, appKey string) string {
	return fmt.Sprintf("datadog:\n  host: %q\n  api_key: %q\n  app_key: %q\n", host, apiKey, appKey)
}

func startDatadog(t *testing.T, eventStatus int) (*datadogAPI, *sidekick) {
	t.Helper()
	api := &datadogAPI{eventStatus: eventStatus}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	sk := startSidekick(t, datadogConfig(server.URL, datadogAPIKey, datadogAppKey))
	return api, sk
}

func TestDatadogDeliversAlertEvent(t *testing.T) {
	api, sk := startDatadog(t, http.StatusAccepted)

	marker := newMarker(t)
	before := time.Now()
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "datadog", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	events, rejected, keyChecks := api.snapshot()
	require.Empty(t, rejected)
	assert.Equal(t, 1, keyChecks, "the startup probe validates both keys")
	require.Len(t, events, 1)
	attrs := events[0].Data.Attributes
	assert.Equal(t, "E2E "+marker, attrs.Title)
	assert.Equal(t, "e2e event "+marker, attrs.Message)
	assert.Equal(t, "e2e-host", attrs.Host)
	assert.Equal(t, "warn", attrs.Attributes.Status)
	assert.Equal(t, "4", attrs.Attributes.Priority)
	assert.NotEmpty(t, attrs.AggregationKey)
	ts, err := time.Parse(time.RFC3339Nano, attrs.Timestamp)
	require.NoError(t, err)
	assert.WithinDuration(t, before, ts, 5*time.Second, "the timestamp is the event time")
	assert.Equal(t, []string{"falco_source:syscall", "e2e"}, attrs.Tags)
	assert.Equal(t, map[string]any{"output_fields": map[string]any{"e2e.marker": marker, "proc.name": "e2e"}}, attrs.Attributes.Custom)
	logs := sk.logs.String()
	assert.NotContains(t, logs, datadogAPIKey)
	assert.NotContains(t, logs, datadogAppKey)
}

func TestDatadogReportsRejectedEvent(t *testing.T) {
	api, sk := startDatadog(t, http.StatusBadRequest)

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "datadog", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 400")
	assert.NotContains(t, st.LastError, datadogAPIKey)
	assert.NotContains(t, sk.logs.String(), datadogAPIKey)

	events, rejected, _ := api.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, events, 1, "max_attempts 1 sends exactly once")
}

func TestDatadogRejectedKeyStartsDegraded(t *testing.T) {
	for _, tc := range []struct{ name, apiKey, appKey string }{
		{name: "api key", apiKey: "wrongDatadogKey", appKey: datadogAppKey},
		{name: "application key", apiKey: datadogAPIKey, appKey: "wrongDatadogAppKey"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &datadogAPI{eventStatus: http.StatusAccepted}
			server := httptest.NewServer(api)
			t.Cleanup(server.Close)
			suffix := newMarker(t)

			_, logs := startSidekickDegraded(t, "datadog", datadogConfig(server.URL, tc.apiKey+suffix, tc.appKey+suffix))
			assert.Contains(t, logs, "HTTP 403")
			assert.NotContains(t, logs, suffix)

			events, _, _ := api.snapshot()
			assert.Empty(t, events)
		})
	}
}

func TestDatadogRequiresAppKey(t *testing.T) {
	logs := startSidekickFails(t, fmt.Sprintf("datadog:\n  host: \"http://127.0.0.1:%d\"\n  api_key: %q\n", freePort(t), datadogAPIKey))
	assert.Contains(t, logs, "app_key: is required")
	assert.NotContains(t, logs, datadogAPIKey)
}

func TestDatadogUnreachableStartsDegraded(t *testing.T) {
	sk := startSidekick(t, datadogConfig(fmt.Sprintf("http://127.0.0.1:%d", freePort(t)), datadogAPIKey, datadogAppKey))
	st := sk.status(t, "datadog")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "health check failed before start")
	assert.NotContains(t, st.LastWarning, datadogAPIKey)
	assert.NotContains(t, sk.logs.String(), datadogAPIKey)
	assert.NotContains(t, sk.logs.String(), datadogAppKey)
}

func TestDatadogKeysAbsentFromAPI(t *testing.T) {
	_, sk := startDatadog(t, http.StatusAccepted)
	for _, path := range []string{"/api/v1/config", "/api/v1/pipeline/outputs/datadog", "/api/v1/pipeline/status/datadog"} {
		resp, err := httpDo(http.MethodGet, sk.apiURL+path, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		assert.NotContains(t, string(body), datadogAPIKey, path)
		assert.NotContains(t, string(body), datadogAppKey, path)
	}
}
