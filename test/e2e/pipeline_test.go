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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// D2: the API answers only on the management listener; ingestion keeps events, health and metrics.
func TestManagementListenerIsSeparate(t *testing.T) {
	sk := startSidekick(t, outputYAML("inmemory", "capacity: 10"))
	for _, tc := range []struct {
		base, path string
		want       int
	}{
		{base: sk.url, path: "/api/v1/pipeline/status", want: http.StatusNotFound},
		{base: sk.url, path: "/api/v1/config", want: http.StatusNotFound},
		{base: sk.url, path: "/metrics", want: http.StatusOK},
		{base: sk.apiURL, path: "/api/v1/pipeline/status", want: http.StatusOK},
		{base: sk.apiURL, path: "/metrics", want: http.StatusNotFound},
	} {
		resp, err := httpDo(http.MethodGet, tc.base+tc.path, nil)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, tc.want, resp.StatusCode, "%s%s", tc.base, tc.path)
	}
	assert.Contains(t, sk.logs.String(), `"management_address":"127.0.0.1:`, "the API listens on loopback by default")
}

// D3: an API write may name a secret file only inside api.secret_dirs, and a write based on an old
// version is refused instead of overwriting the newer one.
func TestAPIWriteReadsSecretsOnlyFromSecretDirs(t *testing.T) {
	tokens := make(chan string, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)
	secrets, outside := t.TempDir(), t.TempDir()
	inside := filepath.Join(secrets, "token")
	require.NoError(t, os.WriteFile(inside, []byte("from-secret-dir\n"), 0o600))
	stranger := filepath.Join(outside, "token")
	require.NoError(t, os.WriteFile(stranger, []byte("outside-private"), 0o600))

	core := withExtra("api:\n  allow_writes: true\n  secret_dirs: [\"" + secrets + "\"]\n")
	sk := startSidekickWith(t, core, outputYAML("inmemory", "capacity: 10"))
	put := func(version int, file string) (int, string) {
		body := fmt.Sprintf(`{"version":%d,"config":{"host":%q,"bearer_token_file":%q,"runtime":{"health_check":false}}}`,
			version, receiver.URL, file)
		resp, err := httpDo(http.MethodPut, sk.apiURL+"/api/v1/pipeline/outputs/webhook", []byte(body))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		answer, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, string(answer)
	}

	status, answer := put(0, stranger)
	assert.Equal(t, http.StatusBadRequest, status, answer)
	assert.Contains(t, answer, "inside api.secret_dirs")

	status, answer = put(0, inside)
	require.Equal(t, http.StatusOK, status, answer)
	assert.NotContains(t, answer, "from-secret-dir")
	sk.postEvent(t, newMarker(t))
	select {
	case token := <-tokens:
		assert.Equal(t, "Bearer from-secret-dir", token)
	case <-time.After(10 * time.Second):
		t.Fatal("the webhook received nothing")
	}

	status, answer = put(0, inside)
	assert.Equal(t, http.StatusConflict, status, answer)
	assert.NotContains(t, sk.logs.String(), "outside-private")
}

// minimum_priority accepts any case; before, an unknown spelling ranked lowest and filtered nothing.
func TestMinimumPriorityIgnoresCase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(server.Close)
	host := "host: \"" + server.URL + "\""
	sk := startSidekick(t, outputYAML("webhook", host)+outputYAML("talon", host+"\nruntime:\n  minimum_priority: CRITICAL"))
	sk.postEvent(t, newMarker(t))
	sk.waitStatus(t, "webhook", func(st outputStatus) bool { return st.SentTotal == 1 })
	st := sk.status(t, "talon")
	assert.Zero(t, st.SentTotal+st.FailedTotal+st.DroppedTotal, "a Warning event stays below CRITICAL")
}

// A reload replaces the output: counters and the last outcome carry over, new events reach the new destination.
func TestReloadCarriesStatusToTheReplacement(t *testing.T) {
	var oldCalls, newCalls atomic.Int32
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		oldCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		newCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(healthy.Close)

	webhook := func(url string) string { return outputYAML("webhook", "host: \""+url+"\"\nruntime:\n  health_check: false") }
	sk := startSidekick(t, webhook(failing.URL))
	sk.postEvent(t, newMarker(t))
	before := sk.waitStatus(t, "webhook", func(st outputStatus) bool { return st.FailedTotal == 1 })
	require.NotEmpty(t, before.LastError)

	sk.reloadOutputs(t, webhook(healthy.URL))
	eventuallyf(t, func() bool { return strings.Contains(sk.logs.String(), "reload complete") }, "reload logged")
	st := sk.status(t, "webhook")
	assert.Equal(t, 1, st.FailedTotal, "counters carry over")
	assert.Equal(t, before.LastError, st.LastError, "the last outcome carries over until the replacement has one")

	sk.postEvent(t, newMarker(t))
	st = sk.waitStatus(t, "webhook", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Empty(t, st.LastError)
	assert.Equal(t, int32(1), newCalls.Load())
	assert.Equal(t, int32(1), oldCalls.Load(), "the old destination gets nothing after the reload")
}

// D8: rule values beyond metrics.max_label_values share the "other" series.
func TestMetricLabelsAreBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(server.Close)
	sk := startSidekickWith(t, withExtra("metrics:\n  max_label_values: 2\n"), outputYAML("webhook", "host: \""+server.URL+"\""))
	for range 3 {
		sk.postEvent(t, newMarker(t))
	}
	sk.waitStatus(t, "webhook", func(st outputStatus) bool { return st.SentTotal == 3 })

	resp, err := httpDo(http.MethodGet, sk.url+"/metrics", nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	metrics := string(body)
	assert.Contains(t, metrics, `rule="other"`)
	assert.Contains(t, metrics, `falcosidekick_metric_label_overflow_total{label="rule"} 1`)
	assert.Contains(t, metrics, `falcosidekick_output_total{output="webhook",status="ok"} 3`)
}

// An outage opens the circuit; the queue waits and is delivered once the destination recovers.
func TestOpenCircuitKeepsTheQueue(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	var delivered atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	sk := startSidekick(t, outputYAML("webhook", "host: \""+server.URL+"\"\nruntime:\n  health_check: false\n"+
		"  circuit_breaker:\n    failure_threshold: 1\n    success_threshold: 1\n    reset_timeout: 1s"))
	const events = 5
	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "webhook", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Equal(t, "error", st.Status)
	for range events - 1 {
		sk.postEvent(t, newMarker(t))
	}
	st = sk.status(t, "webhook")
	assert.Equal(t, 1, st.FailedTotal, "queued events are not failed while the circuit is open")

	down.Store(false)
	st = sk.waitStatus(t, "webhook", func(st outputStatus) bool { return st.SentTotal == events-1 })
	assert.Equal(t, 1, st.FailedTotal)
	assert.Zero(t, st.DroppedTotal)
	assert.Equal(t, int32(events-1), delivered.Load())
}
