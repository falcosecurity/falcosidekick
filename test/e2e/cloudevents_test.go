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
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cloudEventsToken = "e2eCloudEventsToken"
	cloudEventsPath  = "/hooks/" + cloudEventsToken
)

var (
	// https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md#attribute-naming-convention
	cloudEventsAttrName = regexp.MustCompile(`^[a-z0-9]+$`)
	// https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/http-protocol-binding.md#3132-http-header-values
	cloudEventsHeaderValue = regexp.MustCompile(`^(?:[\x21\x23-\x24\x26-\x7e]|%[0-9A-Fa-f]{2})*$`)
)

type cloudEvent struct {
	attributes map[string]string
	data       map[string]any
}

// cloudEventsReceiver is a strict CloudEvents 1.0 HTTP receiver in binary content mode.
type cloudEventsReceiver struct {
	events   []cloudEvent
	rejected []string
	status   int
	mu       sync.Mutex
}

func (r *cloudEventsReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	reject := func(status int, reason string) {
		r.rejected = append(r.rejected, req.Method+" "+req.URL.Path+": "+reason)
		w.WriteHeader(status)
	}
	if req.URL.Path != cloudEventsPath {
		reject(http.StatusNotFound, "unknown path")
		return
	}
	if req.Method != http.MethodPost {
		reject(http.StatusMethodNotAllowed, "method")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusUnsupportedMediaType, "content type "+req.Header.Get("Content-Type"))
		return
	}
	attrs, reason := cloudEventsAttributes(req.Header)
	if reason != "" {
		reject(http.StatusBadRequest, reason)
		return
	}
	var data map[string]any
	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		reject(http.StatusBadRequest, "data: "+err.Error())
		return
	}
	r.events = append(r.events, cloudEvent{attributes: attrs, data: data})
	w.WriteHeader(r.status)
}

func cloudEventsAttributes(header http.Header) (attrs map[string]string, reason string) {
	attrs = map[string]string{}
	for key, values := range header {
		lower := strings.ToLower(key)
		if !strings.HasPrefix(lower, "ce-") {
			continue
		}
		name := strings.TrimPrefix(lower, "ce-")
		if !cloudEventsAttrName.MatchString(name) {
			return nil, "attribute name " + name
		}
		if len(values) != 1 {
			return nil, "repeated attribute " + name
		}
		if !cloudEventsHeaderValue.MatchString(values[0]) {
			return nil, "attribute " + name + " is not percent-encoded"
		}
		decoded, err := url.PathUnescape(values[0])
		if err != nil {
			return nil, "attribute " + name + ": " + err.Error()
		}
		if !utf8.ValidString(decoded) || strings.ContainsFunc(decoded, unicode.IsControl) {
			return nil, "attribute " + name + " is not a CloudEvents String"
		}
		attrs[name] = decoded
	}
	if _, ok := attrs["datacontenttype"]; ok {
		return nil, "ce-datacontenttype must not be sent in binary mode"
	}
	if attrs["specversion"] != "1.0" {
		return nil, "specversion " + attrs["specversion"]
	}
	for _, required := range []string{"id", "source", "type"} {
		if attrs[required] == "" {
			return nil, "missing " + required
		}
	}
	if _, err := url.Parse(attrs["source"]); err != nil {
		return nil, "source is not a URI reference"
	}
	if t, ok := attrs["time"]; ok {
		if _, err := time.Parse(time.RFC3339, t); err != nil {
			return nil, "time is not RFC 3339"
		}
	}
	return attrs, ""
}

func (r *cloudEventsReceiver) snapshot() (events []cloudEvent, rejected []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]cloudEvent(nil), r.events...), append([]string(nil), r.rejected...)
}

func startCloudEvents(t *testing.T, status int, extra string) (*cloudEventsReceiver, *sidekick) {
	t.Helper()
	receiver := &cloudEventsReceiver{status: status}
	server := httptest.NewServer(receiver)
	t.Cleanup(server.Close)
	sk := startSidekick(t, fmt.Sprintf("cloudevents:\n  host: %q\n  secret_endpoint: %q\n  source: /falcosidekick/e2e\n",
		server.URL, cloudEventsPath)+extra)
	return receiver, sk
}

func TestCloudEventsRequiresSource(t *testing.T) {
	logs := startSidekickFails(t,
		fmt.Sprintf("cloudevents:\n  host: \"http://127.0.0.1:%d\"\n  secret_endpoint: %q\n", freePort(t), cloudEventsPath))
	assert.Contains(t, logs, "source: is required")
	assert.NotContains(t, logs, cloudEventsToken)
}

func TestCloudEventsDeliversEvent(t *testing.T) {
	receiver, sk := startCloudEvents(t, http.StatusAccepted, "  extensions:\n    team: \"sec ops\"\n")

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "cloudevents", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	events, rejected := receiver.snapshot()
	require.Empty(t, rejected)
	require.Len(t, events, 1)
	attrs, data := events[0].attributes, events[0].data
	assert.Equal(t, "/falcosidekick/e2e", attrs["source"])
	assert.Equal(t, "org.falco.rule.output.v1", attrs["type"])
	assert.Equal(t, data["uuid"], attrs["id"], "the event id is the Falco event uuid")
	ceTime, err := time.Parse(time.RFC3339Nano, attrs["time"])
	require.NoError(t, err)
	eventTime, err := time.Parse(time.RFC3339Nano, data["time"].(string))
	require.NoError(t, err)
	assert.True(t, ceTime.Equal(eventTime), "the CloudEvents time is the event time")
	assert.Equal(t, "Warning", attrs["priority"])
	assert.Equal(t, "E2E "+marker, attrs["rule"])
	assert.Equal(t, "syscall", attrs["eventsource"])
	assert.Equal(t, "e2e-host", attrs["hostname"])
	assert.Equal(t, "sec ops", attrs["team"])
	assert.Equal(t, "E2E "+marker, data["rule"])
	assert.Equal(t, marker, data["output_fields"].(map[string]any)["e2e.marker"])
	assert.NotContains(t, sk.logs.String(), cloudEventsToken)
}

func TestCloudEventsReportsDestinationFailure(t *testing.T) {
	receiver, sk := startCloudEvents(t, http.StatusInternalServerError, "")

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "cloudevents", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 500")
	assert.NotContains(t, st.LastError, cloudEventsToken)
	assert.NotContains(t, sk.logs.String(), cloudEventsToken)

	events, rejected := receiver.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, events, 1, "max_attempts 1 sends exactly once")
}

// A receiver has no standard probe, so an unreachable host fails only on delivery.
func TestCloudEventsUnreachableAtStartup(t *testing.T) {
	sk := startSidekick(t, fmt.Sprintf("cloudevents:\n  host: \"http://127.0.0.1:%d\"\n  secret_endpoint: %q\n  source: /falcosidekick\n",
		freePort(t), cloudEventsPath))
	assert.Equal(t, "idle", sk.status(t, "cloudevents").Status, "no probe, so not degraded")

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "cloudevents", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.NotEmpty(t, st.LastError)
	assert.NotContains(t, st.LastError, cloudEventsToken)
	assert.NotContains(t, sk.logs.String(), cloudEventsToken)
}

func TestCloudEventsSecretAbsentFromAPI(t *testing.T) {
	_, sk := startCloudEvents(t, http.StatusOK, "")
	for _, path := range []string{"/api/v1/config", "/api/v1/pipeline/outputs/cloudevents", "/api/v1/pipeline/status/cloudevents"} {
		resp, err := httpDo(http.MethodGet, sk.apiURL+path, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		assert.NotContains(t, string(body), cloudEventsToken, path)
	}
}
