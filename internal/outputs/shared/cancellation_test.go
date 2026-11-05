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

package shared_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	cancelAfter  = 200 * time.Millisecond
	returnWithin = 2 * time.Second
)

// hangingHTTPServer accepts every request and never answers until the test
// ends, like a destination that stopped responding.
func hangingHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
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
	return server
}

// hangingTCPServer accepts connections and never writes, like a Kafka broker
// that stopped responding.
func hangingTCPServer(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	conns := make(chan net.Conn, 64)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- conn
		}
	}()
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
		for {
			select {
			case conn := <-conns:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	return ln.Addr().String()
}

// requireReturnsOnCancel runs call with a context that expires after
// cancelAfter and requires it to fail within returnWithin.
func requireReturnsOnCancel(t *testing.T, name string, call func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cancelAfter)
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- call(ctx) }()
	select {
	case err := <-done:
		assert.Error(t, err, "%s must fail when its context expires", name)
		assert.Less(t, time.Since(start), returnWithin, name)
	case <-time.After(returnWithin):
		t.Fatalf("%s did not return within %s of a %s context", name, returnWithin, cancelAfter)
	}
}

// Every driver must stop waiting on a silent destination once its context
// ends, or retire and shutdown deadlines cannot hold.
func TestDriversReturnWhenContextEndsOnSilentDestination(t *testing.T) {
	tests := []struct {
		config func(host string) map[string]any
		name   string
		tcp    bool
	}{
		{name: "webhook", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "slack", config: func(h string) map[string]any { return map[string]any{"host": h, "secret_endpoint": "/services/T/B/X"} }},
		{name: "loki", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "elasticsearch", config: func(h string) map[string]any { return map[string]any{"host": h} }},
		{name: "alertmanager", config: func(h string) map[string]any { return map[string]any{"hosts": []string{h, h}} }},
		{name: "kafka", tcp: true, config: func(h string) map[string]any {
			return map[string]any{"brokers": []string{h}, "topic": "falco"}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var host string
			if tt.tcp {
				host = hangingTCPServer(t)
			} else {
				host = hangingHTTPServer(t).URL
			}
			driver, err := outputTypes[tt.name].New(tt.config(host), output.Deps{})
			require.NoError(t, err)
			require.NoError(t, driver.Init(context.Background()))
			t.Cleanup(func() { _ = driver.Close() })

			requireReturnsOnCancel(t, "Send", func(ctx context.Context) error {
				return driver.Send(ctx, testutil.CreateValidEvent())
			})
			if batch, ok := driver.(output.BatchSender); ok {
				requireReturnsOnCancel(t, "SendBatch", func(ctx context.Context) error {
					return batch.SendBatch(ctx, []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()})
				})
			}
			if tt.name != "webhook" && tt.name != "slack" {
				requireReturnsOnCancel(t, "HealthCheck", driver.HealthCheck)
			}
		})
	}
}
