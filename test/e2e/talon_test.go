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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// talonEvent mirrors the event Falco Talon decodes, plus the uuid
// falcosidekick adds:
// https://github.com/falcosecurity/falco-talon/blob/main/internal/events/events.go
type talonEvent struct {
	Time         time.Time      `json:"time"`
	OutputFields map[string]any `json:"output_fields"`
	UUID         string         `json:"uuid"`
	Output       string         `json:"output"`
	Priority     string         `json:"priority"`
	Rule         string         `json:"rule"`
	Hostname     string         `json:"hostname"`
	Source       string         `json:"source"`
	Tags         []string       `json:"tags"`
}

// talonServer is a strict fake of the Falco Talon HTTP server:
// https://github.com/falcosecurity/falco-talon/blob/main/internal/handler/handler.go
type talonServer struct {
	events   []talonEvent
	rejected []string
	health   int
	status   int
	mu       sync.Mutex
}

func (s *talonServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reject := func(status int, reason string) {
		s.rejected = append(s.rejected, req.Method+" "+req.URL.Path+": "+reason)
		w.WriteHeader(status)
	}
	switch req.URL.Path {
	case "/healthz":
		if req.Method != http.MethodGet {
			reject(http.StatusMethodNotAllowed, "health method")
			return
		}
		s.health++
		_, _ = io.WriteString(w, `{"status": "ok"}`)
		return
	case "/":
	default:
		reject(http.StatusNotFound, "unknown path")
		return
	}
	if req.Method != http.MethodPost {
		reject(http.StatusBadRequest, "Please send with POST http method")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusBadRequest, "content type "+req.Header.Get("Content-Type"))
		return
	}
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	var evt talonEvent
	if err := dec.Decode(&evt); err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	if dec.More() {
		reject(http.StatusBadRequest, "trailing data")
		return
	}
	if evt.Rule == "" || evt.Time.IsZero() || evt.Priority == "" || len(evt.OutputFields) == 0 {
		reject(http.StatusBadRequest, "incomplete Falco event")
		return
	}
	s.events = append(s.events, evt)
	w.WriteHeader(s.status)
}

func (s *talonServer) snapshot() (events []talonEvent, rejected []string, health int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]talonEvent(nil), s.events...), append([]string(nil), s.rejected...), s.health
}

func startTalon(t *testing.T, status int) (talon *talonServer, url string) {
	t.Helper()
	talon = &talonServer{status: status}
	server := httptest.NewServer(talon)
	t.Cleanup(server.Close)
	return talon, server.URL
}

func TestTalonDeliversEvent(t *testing.T) {
	talon, url := startTalon(t, http.StatusOK)
	sk := startSidekick(t, fmt.Sprintf("talon:\n  host: %q\n", url))
	assert.Equal(t, "idle", sk.status(t, "talon").Status, "the health probe passed")

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "talon", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	events, rejected, health := talon.snapshot()
	require.Empty(t, rejected)
	assert.Positive(t, health, "startup probes /healthz")
	require.Len(t, events, 1)
	evt := events[0]
	assert.Equal(t, "E2E "+marker, evt.Rule)
	assert.Equal(t, "Warning", evt.Priority, "priority is sent as Falco sends it")
	assert.Equal(t, "e2e event "+marker, evt.Output)
	assert.Equal(t, "syscall", evt.Source)
	assert.Equal(t, "e2e-host", evt.Hostname)
	assert.Equal(t, []string{"e2e"}, evt.Tags)
	assert.NotEmpty(t, evt.UUID)
	assert.Equal(t, marker, evt.OutputFields["e2e.marker"])
}

func TestTalonReportsDestinationFailure(t *testing.T) {
	talon, url := startTalon(t, http.StatusInternalServerError)
	sk := startSidekick(t, fmt.Sprintf("talon:\n  host: %q\n", url))

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "talon", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 500")
	events, rejected, _ := talon.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, events, 1, "max_attempts 1 sends exactly once")
}

// A wrong base path makes /healthz answer 404, which stops startup.
func TestTalonWrongBasePathFailsStartup(t *testing.T) {
	_, url := startTalon(t, http.StatusOK)
	logs := startSidekickFails(t, fmt.Sprintf("talon:\n  host: %q\n  base_path: /missing\n", url))
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "HTTP 404")
}

func TestTalonUnreachableAtStartupDegrades(t *testing.T) {
	sk := startSidekick(t, "talon:\n  host: \"http://127.0.0.1:1\"\n")
	st := sk.status(t, "talon")
	assert.Equal(t, "degraded", st.Status, "an unreachable Talon at startup is transient")
	assert.Contains(t, st.LastWarning, "health check failed before start")
}

func TestTalonSecretAbsentFromLogsAndAPI(t *testing.T) {
	const secret = "e2eTalonProxyToken"
	talon, url := startTalon(t, http.StatusOK)
	sk := startSidekick(t, fmt.Sprintf("talon:\n  host: %q\n  headers:\n    X-Proxy-Token:\n      secrets: [%q]\n", url, secret))

	sk.postEvent(t, newMarker(t))
	sk.waitStatus(t, "talon", func(st outputStatus) bool { return st.SentTotal == 1 })
	_, rejected, _ := talon.snapshot()
	require.Empty(t, rejected)
	for _, path := range []string{"/api/v1/config", "/api/v1/pipeline/outputs/talon", "/api/v1/pipeline/status/talon"} {
		resp, err := httpDo(http.MethodGet, sk.url+path, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		assert.NotContains(t, string(body), secret, path)
	}
	assert.NotContains(t, sk.logs.String(), secret)
}
