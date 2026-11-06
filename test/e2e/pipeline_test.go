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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
