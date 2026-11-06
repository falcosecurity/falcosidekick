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

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDebounce = 100 * time.Millisecond

func startWatcher(t *testing.T, paths []string) *atomic.Int64 {
	t.Helper()
	var calls atomic.Int64
	w := NewWatcher(paths, testDebounce, func() error {
		calls.Add(1)
		return nil
	}, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-w.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("watcher not ready")
	}
	return &calls
}

func waitCalls(t *testing.T, calls *atomic.Int64, want int64, msg string) {
	t.Helper()
	require.Eventually(t, func() bool { return calls.Load() >= want }, 5*time.Second, 10*time.Millisecond, msg)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestWatcherTriggersReloadOnFileWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outputs.yaml")
	writeFile(t, path, "outputs: {}")
	calls := startWatcher(t, []string{path})

	writeFile(t, path, "outputs:\n  slack: {}")
	waitCalls(t, calls, 1, "a write must trigger a reload")
}

func TestWatcherTriggersReloadOnAtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeFile(t, path, "outputs: {}")
	calls := startWatcher(t, []string{path})

	for i, content := range []string{"outputs:\n  slack: {}", "outputs:\n  loki: {}"} {
		tmp := filepath.Join(dir, "outputs.yaml.tmp")
		writeFile(t, tmp, content)
		require.NoError(t, os.Rename(tmp, path))
		waitCalls(t, calls, int64(i+1), "every atomic rename must trigger a reload, the inode changes each time")
	}
}

// Kubernetes mounts a ConfigMap as dir/outputs.yaml -> ..data/outputs.yaml
// and ..data -> ..<timestamp>; an update swaps ..data only.
func TestWatcherTriggersReloadOnConfigMapSwap(t *testing.T) {
	dir := t.TempDir()
	version := func(name, content string) {
		require.NoError(t, os.Mkdir(filepath.Join(dir, name), 0o700))
		writeFile(t, filepath.Join(dir, name, "outputs.yaml"), content)
	}
	version("..2026_11_05_v1", "outputs: {}")
	require.NoError(t, os.Symlink("..2026_11_05_v1", filepath.Join(dir, "..data")))
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.Symlink(filepath.Join("..data", "outputs.yaml"), path))
	calls := startWatcher(t, []string{path})

	version("..2026_11_05_v2", "outputs:\n  slack: {}")
	require.NoError(t, os.Symlink("..2026_11_05_v2", filepath.Join(dir, "..data_tmp")))
	require.NoError(t, os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")))

	waitCalls(t, calls, 1, "a ConfigMap update must trigger a reload")
}

func TestWatcherStopsOnContextCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outputs.yaml")
	writeFile(t, path, "outputs: {}")
	w := NewWatcher([]string{path}, testDebounce, func() error { return nil }, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	<-w.Ready()
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop on context cancel")
	}
}

func TestWatcherFailsOnMissingDirectory(t *testing.T) {
	w := NewWatcher([]string{filepath.Join(t.TempDir(), "missing", "outputs.yaml")}, testDebounce, func() error { return nil }, slog.Default())
	require.Error(t, w.Run(context.Background()))
	select {
	case <-w.Ready():
		t.Fatal("Ready must stay open when watching failed")
	default:
	}
}

type loopHarness struct {
	events chan fsnotify.Event
	calls  atomic.Int64
}

func runLoop(t *testing.T, paths []string) (*loopHarness, context.CancelFunc) {
	t.Helper()
	h := &loopHarness{events: make(chan fsnotify.Event)}
	w := NewWatcher(paths, testDebounce, func() error {
		h.calls.Add(1)
		return nil
	}, slog.Default())
	w.resolveTargets()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.loop(ctx, h.events, make(chan error)) }()
	return h, cancel
}

func TestWatcherDebounceCoalesces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outputs.yaml")
	writeFile(t, path, "outputs: {}")
	synctest.Test(t, func(t *testing.T) {
		h, cancel := runLoop(t, []string{path})
		defer cancel()

		for range 5 {
			h.events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
			time.Sleep(testDebounce / 2)
		}
		synctest.Wait()
		assert.Zero(t, h.calls.Load(), "no reload while writes keep arriving within the debounce")

		time.Sleep(testDebounce)
		synctest.Wait()
		assert.Equal(t, int64(1), h.calls.Load(), "rapid writes coalesce into one reload")

		h.events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
		time.Sleep(testDebounce)
		synctest.Wait()
		assert.Equal(t, int64(2), h.calls.Load(), "a later write reloads again")
	})
}

// kqueue reports the new version directory but nothing for the later ..data rename.
func TestWatcherReloadsWhenTargetChangesAfterTheLastEvent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "..v1"), 0o700))
	writeFile(t, filepath.Join(dir, "..v1", "outputs.yaml"), "outputs: {}")
	require.NoError(t, os.Symlink("..v1", filepath.Join(dir, "..data")))
	path := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.Symlink(filepath.Join("..data", "outputs.yaml"), path))

	synctest.Test(t, func(t *testing.T) {
		h, cancel := runLoop(t, []string{path})
		defer cancel()

		require.NoError(t, os.Mkdir(filepath.Join(dir, "..v2"), 0o700))
		writeFile(t, filepath.Join(dir, "..v2", "outputs.yaml"), "outputs:\n  slack: {}")
		h.events <- fsnotify.Event{Name: filepath.Join(dir, "..v2"), Op: fsnotify.Create}
		require.NoError(t, os.Symlink("..v2", filepath.Join(dir, "..data_tmp")))
		require.NoError(t, os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")))

		time.Sleep(2 * testDebounce)
		synctest.Wait()
		assert.Equal(t, int64(1), h.calls.Load())
	})
}

func TestWatcherFiltersEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeFile(t, path, "outputs: {}")
	tests := []struct {
		name string
		ev   fsnotify.Event
		want int64
	}{
		{name: "write", ev: fsnotify.Event{Name: path, Op: fsnotify.Write}, want: 1},
		{name: "create", ev: fsnotify.Event{Name: path, Op: fsnotify.Create}, want: 1},
		{name: "rename", ev: fsnotify.Event{Name: path, Op: fsnotify.Rename}, want: 1},
		{name: "chmod", ev: fsnotify.Event{Name: path, Op: fsnotify.Chmod}},
		{name: "unrelated file", ev: fsnotify.Event{Name: filepath.Join(dir, "other.txt"), Op: fsnotify.Write}},
		{name: "same name in another directory", ev: fsnotify.Event{Name: filepath.Join(dir, "sub", "outputs.yaml"), Op: fsnotify.Write}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h, cancel := runLoop(t, []string{path})
				defer cancel()
				h.events <- tt.ev
				time.Sleep(2 * testDebounce)
				synctest.Wait()
				assert.Equal(t, tt.want, h.calls.Load())
			})
		})
	}
}
