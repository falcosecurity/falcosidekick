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

package testutil

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cancellation bounds used by RequireReturnsOnCancel.
const (
	CancelAfter  = 200 * time.Millisecond
	ReturnWithin = 2 * time.Second
)

// HangingHTTPServer accepts every request and answers none until the test ends.
func HangingHTTPServer(t *testing.T) *httptest.Server {
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

// HangingTCPServer accepts connections and never reads or writes; it returns
// the listener address as host:port.
func HangingTCPServer(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-stopped
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	return ln.Addr().String()
}

// RequireReturnsOnCancel runs call with a context that ends after CancelAfter,
// requires an error within ReturnWithin and returns it.
func RequireReturnsOnCancel(t *testing.T, name string, call func(context.Context) error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), CancelAfter)
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- call(ctx) }()
	select {
	case err := <-done:
		require.Error(t, err, "%s must fail when its context ends", name)
		assert.Less(t, time.Since(start), ReturnWithin, name)
		return err
	case <-time.After(ReturnWithin):
		t.Fatalf("%s did not return within %s of a %s context", name, ReturnWithin, CancelAfter)
		return nil
	}
}
