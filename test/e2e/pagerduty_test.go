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
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pagerdutyRoutingKey = "e2eR0utingKeyS3cretXXXXXXXXXXXXX"

// pagerdutyEvent mirrors the documented Events API v2 trigger body:
// https://docs.pagerduty.com/developer/send-alert-event
type pagerdutyEvent struct {
	RoutingKey  string           `json:"routing_key"`
	EventAction string           `json:"event_action"`
	DedupKey    string           `json:"dedup_key"`
	Client      string           `json:"client"`
	ClientURL   string           `json:"client_url"`
	Payload     pagerdutyPayload `json:"payload"`
	Images      json.RawMessage  `json:"images"`
	Links       json.RawMessage  `json:"links"`
}

type pagerdutyPayload struct {
	CustomDetails map[string]any `json:"custom_details"`
	Summary       string         `json:"summary"`
	Source        string         `json:"source"`
	Severity      string         `json:"severity"`
	Timestamp     string         `json:"timestamp"`
	Component     string         `json:"component"`
	Group         string         `json:"group"`
	Class         string         `json:"class"`
}

var pagerdutySeverities = map[string]bool{"critical": true, "error": true, "warning": true, "info": true}

// pagerdutyEvents is a strict fake of the Events API v2 enqueue endpoint.
// Requests PagerDuty would reject are recorded with their reason and answered
// the way PagerDuty answers them.
type pagerdutyEvents struct {
	events   []pagerdutyEvent
	rejected []string
	status   int
	mu       sync.Mutex
}

func (p *pagerdutyEvents) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	reject := func(status int, reason string) {
		p.rejected = append(p.rejected, req.Method+" "+req.URL.Path+": "+reason)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"status":"invalid event","message":"Event object is invalid"}`)
	}
	if req.URL.Path != "/v2/enqueue" {
		reject(http.StatusNotFound, "unknown path")
		return
	}
	if req.Method != http.MethodPost {
		reject(http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusBadRequest, "content type "+req.Header.Get("Content-Type"))
		return
	}
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	var evt pagerdutyEvent
	if err := dec.Decode(&evt); err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	switch {
	case evt.RoutingKey == "":
		reject(http.StatusBadRequest, "missing routing_key")
		return
	case evt.EventAction != "trigger":
		reject(http.StatusBadRequest, "event_action "+evt.EventAction)
		return
	case evt.Payload.Summary == "" || len([]rune(evt.Payload.Summary)) > 1024:
		reject(http.StatusBadRequest, "summary length")
		return
	case evt.Payload.Source == "":
		reject(http.StatusBadRequest, "missing source")
		return
	case !pagerdutySeverities[evt.Payload.Severity]:
		reject(http.StatusBadRequest, "severity "+evt.Payload.Severity)
		return
	case len(evt.DedupKey) > 255:
		reject(http.StatusBadRequest, "dedup_key length")
		return
	}
	p.events = append(p.events, evt)
	w.WriteHeader(p.status)
	_, _ = fmt.Fprintf(w, `{"status":"success","message":"Event processed","dedup_key":%q}`, evt.DedupKey)
}

func (p *pagerdutyEvents) snapshot() (events []pagerdutyEvent, rejected []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]pagerdutyEvent(nil), p.events...), append([]string(nil), p.rejected...)
}

// startPagerDuty reads the routing key from a file so the _file variant is
// covered end to end.
func startPagerDuty(t *testing.T, status int) (*pagerdutyEvents, *sidekick) {
	t.Helper()
	fake := &pagerdutyEvents{status: status}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	keyFile := filepath.Join(t.TempDir(), "routing_key")
	require.NoError(t, os.WriteFile(keyFile, []byte(pagerdutyRoutingKey+"\n"), 0o600))
	sk := startSidekick(t, fmt.Sprintf("pagerduty:\n  host: %q\n  region: eu\n  routing_key_file: %q\n", server.URL, keyFile))
	return fake, sk
}

func TestPagerDutyDeliversEvent(t *testing.T) {
	fake, sk := startPagerDuty(t, http.StatusAccepted)

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "pagerduty", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	events, rejected := fake.snapshot()
	require.Empty(t, rejected)
	require.Len(t, events, 1)
	evt := events[0]
	assert.Equal(t, pagerdutyRoutingKey, evt.RoutingKey)
	assert.NotEmpty(t, evt.DedupKey)
	assert.Equal(t, "e2e event "+marker, evt.Payload.Summary)
	assert.Equal(t, "e2e-host", evt.Payload.Source)
	assert.Equal(t, "warning", evt.Payload.Severity)
	assert.NotEmpty(t, evt.Payload.Timestamp)
	assert.Equal(t, marker, evt.Payload.CustomDetails["e2e.marker"])
	assert.Equal(t, "E2E "+marker, evt.Payload.CustomDetails["rule"])
	assert.NotContains(t, sk.logs.String(), pagerdutyRoutingKey)
	for _, path := range []string{"/api/v1/pipeline/outputs/pagerduty", "/api/v1/config"} {
		assert.NotContains(t, pagerdutyAPIBody(t, sk, path), pagerdutyRoutingKey, path)
	}
}

func pagerdutyAPIBody(t *testing.T, sk *sidekick, path string) string {
	t.Helper()
	resp, err := httpDo(http.MethodGet, sk.url+path, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, path)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestPagerDutyReportsRejectedEvent(t *testing.T) {
	fake, sk := startPagerDuty(t, http.StatusBadRequest)

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "pagerduty", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 400")
	assert.NotContains(t, st.LastError, pagerdutyRoutingKey)
	assert.NotContains(t, sk.logs.String(), pagerdutyRoutingKey)

	events, rejected := fake.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, events, 1, "max_attempts 1 sends exactly once")
}

// PagerDuty has no probe, so an unreachable host is found at delivery time.
func TestPagerDutyUnreachableFailsAtDelivery(t *testing.T) {
	sk := startSidekick(t, fmt.Sprintf("pagerduty:\n  host: %q\n  routing_key: %q\n",
		fmt.Sprintf("http://127.0.0.1:%d", freePort(t)), pagerdutyRoutingKey))
	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "pagerduty", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Contains(t, st.LastError, "connection refused")
	assert.NotContains(t, sk.logs.String(), pagerdutyRoutingKey)
}
