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
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPollerDetectsContentChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	var calls atomic.Int64
	p := NewPoller([]string{path}, nil, 100*time.Millisecond, func() {
		calls.Add(1)
	}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = p.Run(ctx) }()

	// The first tick only records hashes.
	time.Sleep(50 * time.Millisecond)

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
	p := NewPoller([]string{path}, nil, 100*time.Millisecond, func() {
		calls.Add(1)
	}, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = p.Run(ctx) }()

	time.Sleep(500 * time.Millisecond)

	assert.Equal(t, int64(0), calls.Load(), "poller must not trigger reload when content unchanged")
}

func TestPollerStopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(path, []byte("outputs: {}"), 0o644))

	p := NewPoller([]string{path}, nil, 100*time.Millisecond, func() {}, slog.Default())

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

func TestPollerSecretFiles(t *testing.T) {
	const interval = time.Second
	tests := []struct {
		change func(t *testing.T, dir string, list *dirList)
		name   string
		want   int64
	}{
		{name: "unchanged", change: func(*testing.T, string, *dirList) {}},
		{name: "same content rewritten", change: func(t *testing.T, dir string, _ *dirList) {
			writeFile(t, filepath.Join(dir, "token"), "first")
		}},
		{name: "content changed", want: 1, change: func(t *testing.T, dir string, _ *dirList) {
			writeFile(t, filepath.Join(dir, "token"), "rotated")
		}},
		{name: "new file listed", want: 1, change: func(t *testing.T, dir string, list *dirList) {
			writeFile(t, filepath.Join(dir, "key"), "k")
			list.set(filepath.Join(dir, "token"), filepath.Join(dir, "key"))
		}},
		{name: "file no longer listed", change: func(_ *testing.T, _ string, list *dirList) {
			list.set()
		}},
		{name: "listed file unreadable", change: func(t *testing.T, dir string, _ *dirList) {
			require.NoError(t, os.Remove(filepath.Join(dir, "token")))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "token"), "first")
			list := &dirList{dirs: []string{filepath.Join(dir, "token")}}
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int64
				p := NewPoller(nil, list.get, interval, func() {
					calls.Add(1)
				}, slog.Default())
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go func() { _ = p.Run(ctx) }()
				synctest.Wait()

				tt.change(t, dir, list)
				time.Sleep(interval + time.Millisecond)
				synctest.Wait()
				assert.Equal(t, tt.want, calls.Load())

				time.Sleep(interval)
				synctest.Wait()
				assert.Equal(t, tt.want, calls.Load(), "a change reloads once")
			})
		})
	}
}

// A file that leaves the list and comes back counts as new.
func TestPollerForgetsUnlistedSecretFiles(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	writeFile(t, token, "first")
	config := filepath.Join(dir, "outputs.yaml")
	writeFile(t, config, "outputs: {}")
	list := &dirList{dirs: []string{token, config}}
	var calls atomic.Int64
	p := NewPoller([]string{config}, list.get, time.Second, func() {
		calls.Add(1)
	}, slog.Default())
	p.hashes[config], _ = hashFile(config)
	p.hashes[token], _ = hashSecretFile(token)

	list.set()
	assert.False(t, p.checkForChanges())
	assert.Contains(t, p.hashes, config, "an output config path stays")
	assert.NotContains(t, p.hashes, token)

	list.set(token)
	assert.True(t, p.checkForChanges())
	assert.False(t, p.checkForChanges())
}
