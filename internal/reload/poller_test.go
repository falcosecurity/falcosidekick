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

package reload

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPollerDetectsContentChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	var calls atomic.Int64
	p := NewPoller([]string{path}, 100*time.Millisecond, func() error {
		calls.Add(1)
		return nil
	}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = p.Run(ctx) }()

	// Wait for initial hash computation + first tick.
	time.Sleep(50 * time.Millisecond)

	// Modify file content.
	require.NoError(t, os.WriteFile(path, []byte("outputs:\n  slack: {}"), 0o644))

	assert.Eventually(t, func() bool {
		return calls.Load() >= 1
	}, 2*time.Second, 50*time.Millisecond, "poller must detect content change")
}

func TestPollerSkipsWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	var calls atomic.Int64
	p := NewPoller([]string{path}, 100*time.Millisecond, func() error {
		calls.Add(1)
		return nil
	}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = p.Run(ctx) }()

	// Wait for several poll cycles without changing the file.
	time.Sleep(500 * time.Millisecond)

	assert.Equal(t, int64(0), calls.Load(), "poller must not trigger reload when content unchanged")
}

func TestPollerStopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	p := NewPoller([]string{path}, 100*time.Millisecond, func() error { return nil }, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("poller did not stop on context cancel")
	}
}
