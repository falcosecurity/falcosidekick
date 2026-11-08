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

func TestWatcherTriggersReloadOnFileWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	var calls atomic.Int64
	w := NewWatcher([]string{path}, 50*time.Millisecond, func() error {
		calls.Add(1)
		return nil
	}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = w.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)

	require.NoError(t, os.WriteFile(path, []byte("outputs:\n  slack: {}"), 0o644))

	assert.Eventually(t, func() bool {
		return calls.Load() >= 1
	}, 2*time.Second, 50*time.Millisecond, "watcher must trigger reload after file write")
}

func TestWatcherTriggersReloadOnAtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	var calls atomic.Int64
	w := NewWatcher([]string{path}, 50*time.Millisecond, func() error {
		calls.Add(1)
		return nil
	}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = w.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)

	// Simulate atomic save: write to temp file, then rename over the target.
	tmp := filepath.Join(dir, "outputs.yaml.tmp")
	require.NoError(t, os.WriteFile(tmp, []byte("outputs:\n  slack: {}"), 0o644))
	require.NoError(t, os.Rename(tmp, path))

	assert.Eventually(t, func() bool {
		return calls.Load() >= 1
	}, 2*time.Second, 50*time.Millisecond, "watcher must trigger reload after atomic rename")

	// Second atomic rename must also be detected (inode changes again).
	tmp2 := filepath.Join(dir, "outputs.yaml.tmp2")
	require.NoError(t, os.WriteFile(tmp2, []byte("outputs:\n  loki: {}"), 0o644))
	require.NoError(t, os.Rename(tmp2, path))

	assert.Eventually(t, func() bool {
		return calls.Load() >= 2
	}, 2*time.Second, 50*time.Millisecond, "watcher must detect second atomic rename")
}

func TestWatcherDebounceCoalesces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	var calls atomic.Int64
	w := NewWatcher([]string{path}, 200*time.Millisecond, func() error {
		calls.Add(1)
		return nil
	}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = w.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 5; i++ {
		require.NoError(t, os.WriteFile(path, []byte("outputs:\n  v: "+string(rune('0'+i))), 0o644))
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	assert.Equal(t, int64(1), calls.Load(), "rapid writes must coalesce into single reload")
}

func TestWatcherIgnoresUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	var calls atomic.Int64
	w := NewWatcher([]string{path}, 50*time.Millisecond, func() error {
		calls.Add(1)
		return nil
	}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = w.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)

	// Write to a different file in the same directory.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.txt"), []byte("noise"), 0o644))

	time.Sleep(300 * time.Millisecond)

	assert.Equal(t, int64(0), calls.Load(), "watcher must not trigger on unrelated files")
}

func TestWatcherStopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	w := NewWatcher([]string{path}, 50*time.Millisecond, func() error { return nil }, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not stop on context cancel")
	}
}
