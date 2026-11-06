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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const datadogAPIKey = "e2eDatadogApiKey0123456789abcdef"

// datadogEvent mirrors the Events API v1 request body:
// https://docs.datadoghq.com/api/latest/events/#post-an-event
type datadogEvent struct {
	Title          string   `json:"title"`
	Text           string   `json:"text"`
	AlertType      string   `json:"alert_type"`
	SourceTypeName string   `json:"source_type_name"`
	AggregationKey string   `json:"aggregation_key"`
	DeviceName     string   `json:"device_name"`
	Host           string   `json:"host"`
	Priority       string   `json:"priority"`
	Tags           []string `json:"tags"`
	DateHappened   int64    `json:"date_happened"`
	RelatedEventID int64    `json:"related_event_id"`
}

var datadogAlertTypes = []string{"error", "warning", "info", "success", "user_update", "recommendation", "snapshot"}

const datadogAppKey = "e2eDatadogAppKey0123456789abcdef0123456"

// datadogV2Request mirrors the Events API v2 alert EventCreateRequestPayload:
// https://github.com/DataDog/datadog-api-client-go/blob/master/.generator/schemas/v2/openapi.yaml
type datadogV2Request struct {
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

// datadogAPI is a strict fake that answers 403 to wrong keys, as Datadog does.
type datadogAPI struct {
	key         string
	events      []datadogEvent
	v2Events    []datadogV2Request
	rejected    []string
	validations int
	keyChecks   int
	eventStatus int
	mu          sync.Mutex
}

func (d *datadogAPI) appKeyValid(req *http.Request) bool {
	return req.Header.Get("DD-APPLICATION-KEY") == datadogAppKey
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
	if req.Header.Get("DD-API-KEY") != d.key {
		reject(http.StatusForbidden, "wrong key")
		return
	}
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/api/v1/validate":
		d.validations++
		w.Header().Set("Content-Type", contentTypeJSON)
		_, _ = io.WriteString(w, `{"valid":true}`)
	case req.Method == http.MethodPost && req.URL.Path == "/api/v1/events":
		d.postEvent(w, req, reject)
	case req.Method == http.MethodGet && req.URL.Path == "/api/v2/validate_keys":
		if !d.appKeyValid(req) {
			reject(http.StatusForbidden, "wrong application key")
			return
		}
		d.keyChecks++
		w.Header().Set("Content-Type", contentTypeJSON)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	case req.Method == http.MethodPost && req.URL.Path == "/api/v2/events":
		if !d.appKeyValid(req) {
			reject(http.StatusForbidden, "wrong application key")
			return
		}
		d.postV2Event(w, req, reject)
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
	var evt datadogEvent
	if err := dec.Decode(&evt); err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	switch {
	case dec.More():
		reject(http.StatusBadRequest, "trailing data")
		return
	case evt.Title == "" || evt.Text == "":
		reject(http.StatusBadRequest, "title and text are required")
		return
	case len([]rune(evt.Text)) > 4000:
		reject(http.StatusBadRequest, "text over 4000 characters")
		return
	case evt.AlertType != "" && !slices.Contains(datadogAlertTypes, evt.AlertType):
		reject(http.StatusBadRequest, "alert_type "+evt.AlertType)
		return
	}
	d.events = append(d.events, evt)
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(d.eventStatus)
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (d *datadogAPI) postV2Event(w http.ResponseWriter, req *http.Request, reject func(int, string)) {
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusBadRequest, "content type "+req.Header.Get("Content-Type"))
		return
	}
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	var body datadogV2Request
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
	case !slices.Contains([]string{"warn", "error", "ok"}, attrs.Attributes.Status):
		reject(http.StatusBadRequest, "status "+attrs.Attributes.Status)
	case attrs.Attributes.Priority != "" && !slices.Contains([]string{"1", "2", "3", "4", "5"}, attrs.Attributes.Priority):
		reject(http.StatusBadRequest, "priority "+attrs.Attributes.Priority)
	default:
		if attrs.Timestamp != "" {
			if _, err := time.Parse(time.RFC3339Nano, attrs.Timestamp); err != nil {
				reject(http.StatusBadRequest, "timestamp is not ISO 8601")
				return
			}
		}
		d.v2Events = append(d.v2Events, body)
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(d.eventStatus)
		_, _ = io.WriteString(w, `{"data":{"type":"event","attributes":{"attributes":{"evt":{"uid":"e2e"}}}}}`)
	}
}

func (d *datadogAPI) v2Snapshot() (events []datadogV2Request, rejected []string, keyChecks int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]datadogV2Request(nil), d.v2Events...), append([]string(nil), d.rejected...), d.keyChecks
}

func (d *datadogAPI) snapshot() (events []datadogEvent, rejected []string, validations int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]datadogEvent(nil), d.events...), append([]string(nil), d.rejected...), d.validations
}

func startDatadog(t *testing.T, eventStatus int, key string) (*datadogAPI, *sidekick) {
	t.Helper()
	api := &datadogAPI{eventStatus: eventStatus, key: datadogAPIKey}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	sk := startSidekick(t, fmt.Sprintf("datadog:\n  host: %q\n  api_key: %q\n", server.URL, key))
	return api, sk
}

func TestDatadogDeliversEvent(t *testing.T) {
	api, sk := startDatadog(t, http.StatusAccepted, datadogAPIKey)

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "datadog", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	events, rejected, validations := api.snapshot()
	require.Empty(t, rejected)
	assert.Equal(t, 1, validations, "the startup probe validates the key")
	require.Len(t, events, 1)
	evt := events[0]
	assert.Equal(t, "E2E "+marker, evt.Title)
	assert.Equal(t, "e2e event "+marker, evt.Text)
	assert.Equal(t, "warning", evt.AlertType)
	assert.Equal(t, "falco", evt.SourceTypeName)
	assert.Equal(t, []string{
		"e2e.marker:" + marker, "proc.name:e2e", "source:syscall", "source:falco", "hostname:e2e-host", "e2e",
	}, evt.Tags)
	assert.NotContains(t, sk.logs.String(), datadogAPIKey)
}

func TestDatadogReportsRejectedEvent(t *testing.T) {
	api, sk := startDatadog(t, http.StatusBadRequest, datadogAPIKey)

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

// Datadog answers 403 to an invalid key, which stops startup.
func TestDatadogRejectedKeyFailsStartup(t *testing.T) {
	api := &datadogAPI{eventStatus: http.StatusAccepted, key: datadogAPIKey}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	wrong := "wrongDatadogKey" + newMarker(t)

	logs := startSidekickFails(t, fmt.Sprintf("datadog:\n  host: %q\n  api_key: %q\n", server.URL, wrong))
	assert.Contains(t, logs, "HTTP 403")
	assert.NotContains(t, logs, wrong)

	events, _, _ := api.snapshot()
	assert.Empty(t, events)
}

func TestDatadogUnreachableStartsDegraded(t *testing.T) {
	sk := startSidekick(t, fmt.Sprintf("datadog:\n  host: \"http://127.0.0.1:%d\"\n  api_key: %q\n", freePort(t), datadogAPIKey))
	st := sk.status(t, "datadog")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "health check failed before start")
	assert.NotContains(t, st.LastWarning, datadogAPIKey)
	assert.NotContains(t, sk.logs.String(), datadogAPIKey)
}

func startDatadogV2(t *testing.T, eventStatus int) (*datadogAPI, *sidekick) {
	t.Helper()
	api := &datadogAPI{eventStatus: eventStatus, key: datadogAPIKey}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	sk := startSidekick(t, fmt.Sprintf("datadog:\n  host: %q\n  api_key: %q\n  app_key: %q\n", server.URL, datadogAPIKey, datadogAppKey))
	return api, sk
}

func TestDatadogV2DeliversAlertEvent(t *testing.T) {
	api, sk := startDatadogV2(t, http.StatusAccepted)

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "datadog", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	events, rejected, keyChecks := api.v2Snapshot()
	require.Empty(t, rejected)
	assert.Equal(t, 1, keyChecks, "the startup probe validates both keys")
	v1Events, _, validations := api.snapshot()
	assert.Empty(t, v1Events, "an application key selects Events API v2")
	assert.Equal(t, 1, validations)
	require.Len(t, events, 1)
	attrs := events[0].Data.Attributes
	assert.Equal(t, "E2E "+marker, attrs.Title)
	assert.Equal(t, "e2e event "+marker, attrs.Message)
	assert.Equal(t, "warn", attrs.Attributes.Status)
	assert.Equal(t, "4", attrs.Attributes.Priority)
	assert.NotEmpty(t, attrs.AggregationKey)
	assert.NotEmpty(t, attrs.Timestamp)
	assert.Equal(t, []string{
		"e2e.marker:" + marker, "proc.name:e2e", "source:syscall", "source:falco", "hostname:e2e-host", "e2e",
	}, attrs.Tags)
	logs := sk.logs.String()
	assert.NotContains(t, logs, datadogAPIKey)
	assert.NotContains(t, logs, datadogAppKey)
}

func TestDatadogV2RejectedAppKeyFailsStartup(t *testing.T) {
	api := &datadogAPI{eventStatus: http.StatusAccepted, key: datadogAPIKey}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	wrong := "wrongDatadogAppKey" + newMarker(t)

	logs := startSidekickFails(t, fmt.Sprintf("datadog:\n  host: %q\n  api_key: %q\n  app_key: %q\n", server.URL, datadogAPIKey, wrong))
	assert.Contains(t, logs, "HTTP 403")
	assert.NotContains(t, logs, wrong)
	assert.NotContains(t, logs, datadogAPIKey)

	events, _, _ := api.v2Snapshot()
	assert.Empty(t, events)
}

func TestDatadogV2KeysAbsentFromAPI(t *testing.T) {
	_, sk := startDatadogV2(t, http.StatusAccepted)
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

func TestDatadogKeyAbsentFromAPI(t *testing.T) {
	_, sk := startDatadog(t, http.StatusAccepted, datadogAPIKey)
	for _, path := range []string{"/api/v1/config", "/api/v1/pipeline/outputs/datadog", "/api/v1/pipeline/status/datadog"} {
		resp, err := httpDo(http.MethodGet, sk.apiURL+path, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		assert.NotContains(t, string(body), datadogAPIKey, path)
	}
}
