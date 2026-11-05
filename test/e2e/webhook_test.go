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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webhookReceiver records every request it receives and answers with status.
type webhookReceiver struct {
	bodies  [][]byte
	headers []http.Header
	paths   []string
	status  int
	mu      sync.Mutex
}

func (r *webhookReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bodies = append(r.bodies, body)
	r.headers = append(r.headers, req.Header.Clone())
	r.paths = append(r.paths, req.Method+" "+req.URL.Path)
	w.WriteHeader(r.status)
}

func (r *webhookReceiver) received() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func TestWebhookDeliversEvent(t *testing.T) {
	receiver := &webhookReceiver{status: http.StatusOK}
	server := httptest.NewServer(receiver)
	t.Cleanup(server.Close)
	sk := startSidekick(t, fmt.Sprintf(`webhook:
  host: %q
  endpoint: /falco
  headers:
    X-E2E:
      values: ["yes"]
`, server.URL))

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "webhook", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	require.Equal(t, 1, receiver.received())
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	assert.Equal(t, "POST /falco", receiver.paths[0])
	assert.Equal(t, "yes", receiver.headers[0].Get("X-E2E"))
	assert.Equal(t, "application/json", receiver.headers[0].Get("Content-Type"))
	var got map[string]any
	require.NoError(t, json.Unmarshal(receiver.bodies[0], &got))
	assert.Equal(t, "E2E "+marker, got["rule"])
	assert.NotEmpty(t, got["uuid"])
	assert.Equal(t, marker, got["output_fields"].(map[string]any)["e2e.marker"])
}

func TestWebhookReportsDestinationFailure(t *testing.T) {
	receiver := &webhookReceiver{status: http.StatusInternalServerError}
	server := httptest.NewServer(receiver)
	t.Cleanup(server.Close)
	sk := startSidekick(t, fmt.Sprintf("webhook:\n  host: %q\n", server.URL))

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "webhook", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 500")
	assert.Equal(t, 1, receiver.received(), "max_attempts 1 sends exactly once")
}
