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
	"runtime"
	"slices"
	"sync"
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
	startWatcherWith(t, paths, nil, func() error {
		calls.Add(1)
		return nil
	})
	return &calls
}

func startWatcherWith(t *testing.T, paths []string, dirs func() []string, reloadFn func() error) {
	t.Helper()
	w := NewWatcher(paths, dirs, testDebounce, reloadFn, slog.Default())
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
	w := NewWatcher([]string{path}, nil, testDebounce, func() error { return nil }, slog.Default())

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
	w := NewWatcher([]string{filepath.Join(t.TempDir(), "missing", "outputs.yaml")}, nil, testDebounce, func() error { return nil }, slog.Default())
	require.Error(t, w.Run(context.Background()))
	select {
	case <-w.Ready():
		t.Fatal("Ready must stay open when watching failed")
	default:
	}
}

type loopHarness struct {
	events chan fsnotify.Event
	fs     *fakeDirWatcher
	w      *Watcher
	calls  atomic.Int64
}

// fakeDirWatcher records the watched directories; missing ones fail like fsnotify.
type fakeDirWatcher struct {
	missing map[string]bool
	adds    map[string]int
	dirs    []string
	mu      sync.Mutex
}

func (f *fakeDirWatcher) Add(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing[name] {
		return os.ErrNotExist
	}
	if f.adds == nil {
		f.adds = make(map[string]int)
	}
	f.adds[name]++
	if !slices.Contains(f.dirs, name) {
		f.dirs = append(f.dirs, name)
	}
	return nil
}

func (f *fakeDirWatcher) Remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := slices.Index(f.dirs, name)
	if i < 0 {
		return fsnotify.ErrNonExistentWatch
	}
	f.dirs = slices.Delete(f.dirs, i, i+1)
	return nil
}

func (f *fakeDirWatcher) watched() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(slices.Values(f.dirs))
}

func (f *fakeDirWatcher) setMissing(name string, missing bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing == nil {
		f.missing = make(map[string]bool)
	}
	f.missing[name] = missing
}

func (f *fakeDirWatcher) addCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.adds[name]
}

// dirList is a secret directory list a test changes while the watcher runs.
type dirList struct {
	dirs []string
	mu   sync.Mutex
}

func (l *dirList) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.dirs)
}

func (l *dirList) set(dirs ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dirs = dirs
}

// contentRecorder records the content of file at each reload.
type contentRecorder struct {
	file   string
	values []string
	mu     sync.Mutex
}

func (r *contentRecorder) reload() error {
	data, err := os.ReadFile(r.file)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values = append(r.values, string(data))
	return nil
}

func (r *contentRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.values)
}

func TestWatcherReloadsOnSecretFileWrite(t *testing.T) {
	root := t.TempDir()
	token := filepath.Join(root, "webhook", "token")
	require.NoError(t, os.Mkdir(filepath.Dir(token), 0o700))
	writeFile(t, token, "first")
	rec := &contentRecorder{file: token}
	startWatcherWith(t, nil, NewSecretPaths([]string{root}, nil).Dirs, rec.reload)

	writeFile(t, token, "rotated")
	require.Eventually(t, func() bool { return slices.Equal(rec.seen(), []string{"rotated"}) }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(3 * testDebounce)
	assert.Equal(t, []string{"rotated"}, rec.seen(), "one write reloads once")
}

// The kubelet writes a new version directory, then renames a ..data_tmp link over ..data.
func TestWatcherReloadsOnKubeletSecretSwap(t *testing.T) {
	root := t.TempDir()
	mount := filepath.Join(root, "webhook")
	kubeletMount(t, mount, "..2026_11_08_v1", map[string]string{"token": "first"})
	rec := &contentRecorder{file: filepath.Join(mount, "token")}
	startWatcherWith(t, nil, NewSecretPaths([]string{root}, nil).Dirs, rec.reload)

	kubeletMount(t, mount, "..2026_11_08_v2", map[string]string{"token": "rotated"})
	require.Eventually(t, func() bool { return slices.Contains(rec.seen(), "rotated") }, 5*time.Second, 10*time.Millisecond,
		"a Secret update reloads with the new content")
}

// With the version directory written before, the swap is a link creation and a rename over ..data:
// inotify reports both, kqueue may report neither, so other platforms rely on the poller.
func TestWatcherReloadsOnKubeletLinkRenameAlone(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kqueue reports no event for a rename over an existing entry; the poller covers it")
	}
	root := t.TempDir()
	mount := filepath.Join(root, "webhook")
	kubeletMount(t, mount, "..2026_11_08_v1", map[string]string{"token": "first"})
	require.NoError(t, os.Mkdir(filepath.Join(mount, "..2026_11_08_v2"), 0o700))
	writeFile(t, filepath.Join(mount, "..2026_11_08_v2", "token"), "rotated")
	rec := &contentRecorder{file: filepath.Join(mount, "token")}
	startWatcherWith(t, nil, NewSecretPaths([]string{root}, nil).Dirs, rec.reload)

	require.NoError(t, os.Symlink("..2026_11_08_v2", filepath.Join(mount, "..data_tmp")))
	require.NoError(t, os.Rename(filepath.Join(mount, "..data_tmp"), filepath.Join(mount, "..data")))
	require.Eventually(t, func() bool { return slices.Equal(rec.seen(), []string{"rotated"}) }, 5*time.Second, 10*time.Millisecond)
}

func TestWatcherWatchesANewSecretMount(t *testing.T) {
	root := t.TempDir()
	var calls atomic.Int64
	startWatcherWith(t, nil, NewSecretPaths([]string{root}, nil).Dirs, func() error {
		calls.Add(1)
		return nil
	})

	mount := filepath.Join(root, "slack")
	require.NoError(t, os.Mkdir(mount, 0o700))
	waitCalls(t, &calls, 1, "a new Secret mount reloads")

	// A write before the mount is watched reaches no watch, so the test writes until one does.
	require.Eventually(t, func() bool {
		writeFile(t, filepath.Join(mount, "token"), "t")
		return calls.Load() >= 2
	}, 5*time.Second, 50*time.Millisecond, "a write in the new mount reloads")
}

func TestWatcherStopsOnContextCancelWithSecretDirsOnly(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(t.TempDir(), "missing")
	w := NewWatcher(nil, func() []string { return []string{root, missing} }, testDebounce, func() error { return nil }, slog.Default())
	w.Refresh()
	w.Refresh()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	select {
	case <-w.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("a secret directory that cannot be watched must not stop the watcher")
	}
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop on context cancel")
	}
}

func TestWatcherSecretBurstCoalesces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, cancel := runSecretLoop(t, nil, func() []string { return []string{"/secrets", "/secrets/webhook"} })
		defer cancel()

		for _, name := range []string{"..2026_v2", "..data_tmp", "..data", "..2026_v1", "token"} {
			h.events <- fsnotify.Event{Name: "/secrets/webhook/" + name, Op: fsnotify.Create}
		}
		time.Sleep(testDebounce / 2)
		synctest.Wait()
		assert.Zero(t, h.calls.Load())

		time.Sleep(testDebounce)
		synctest.Wait()
		assert.Equal(t, int64(1), h.calls.Load(), "a kubelet swap reloads once")
	})
}

func TestWatcherSecretEvents(t *testing.T) {
	tests := []struct {
		name string
		ev   fsnotify.Event
		want int64
	}{
		{name: "write in a mount", ev: fsnotify.Event{Name: "/secrets/webhook/token", Op: fsnotify.Write}, want: 1},
		{name: "data link renamed", ev: fsnotify.Event{Name: "/secrets/webhook/..data", Op: fsnotify.Create}, want: 1},
		{name: "file removed", ev: fsnotify.Event{Name: "/secrets/webhook/token", Op: fsnotify.Remove}, want: 1},
		{name: "new mount", ev: fsnotify.Event{Name: "/secrets/slack", Op: fsnotify.Create}, want: 1},
		{name: "mount removed", ev: fsnotify.Event{Name: "/secrets/webhook", Op: fsnotify.Remove}, want: 1},
		{name: "chmod", ev: fsnotify.Event{Name: "/secrets/webhook/token", Op: fsnotify.Chmod}},
		{name: "unwatched directory", ev: fsnotify.Event{Name: "/elsewhere/token", Op: fsnotify.Write}},
		{name: "below a mount", ev: fsnotify.Event{Name: "/secrets/webhook/..2026_v1/token", Op: fsnotify.Write}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h, cancel := runSecretLoop(t, nil, func() []string { return []string{"/secrets", "/secrets/webhook"} })
				defer cancel()
				h.events <- tt.ev
				time.Sleep(2 * testDebounce)
				synctest.Wait()
				assert.Equal(t, tt.want, h.calls.Load())
			})
		})
	}
}

func TestWatcherRefreshSyncsSecretDirs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		list := &dirList{dirs: []string{"/a"}}
		h, cancel := runSecretLoop(t, []string{"/cfg/outputs.yaml"}, list.get)
		defer cancel()
		assert.Equal(t, []string{"/a", "/cfg"}, h.fs.watched())

		h.fs.setMissing("/c", true)
		list.set("/b", "/c/")
		h.w.Refresh()
		synctest.Wait()
		assert.Equal(t, []string{"/b", "/cfg"}, h.fs.watched(), "a directory no longer listed is dropped, a missing one is skipped")

		h.events <- fsnotify.Event{Name: "/a/token", Op: fsnotify.Write}
		time.Sleep(2 * testDebounce)
		synctest.Wait()
		assert.Zero(t, h.calls.Load(), "a dropped directory no longer reloads")

		// The sync after each reload retries the missing directory.
		h.fs.setMissing("/c", false)
		h.events <- fsnotify.Event{Name: "/b/token", Op: fsnotify.Write}
		time.Sleep(2 * testDebounce)
		synctest.Wait()
		assert.Equal(t, int64(1), h.calls.Load())
		assert.Equal(t, []string{"/b", "/c", "/cfg"}, h.fs.watched())

		// A removed directory loses its watch; the next sync adds it again while it is listed.
		h.events <- fsnotify.Event{Name: "/b", Op: fsnotify.Remove}
		time.Sleep(2 * testDebounce)
		synctest.Wait()
		assert.Equal(t, int64(2), h.calls.Load())
		assert.Equal(t, 2, h.fs.addCount("/b"))
		assert.Equal(t, []string{"/b", "/c", "/cfg"}, h.fs.watched())
	})
}

func runLoop(t *testing.T, paths []string) (*loopHarness, context.CancelFunc) {
	t.Helper()
	return runSecretLoop(t, paths, nil)
}

// runSecretLoop runs the loop on fake events; dirs feeds the secret directories.
func runSecretLoop(t *testing.T, paths []string, dirs func() []string) (*loopHarness, context.CancelFunc) {
	t.Helper()
	h := &loopHarness{events: make(chan fsnotify.Event), fs: &fakeDirWatcher{}}
	w := NewWatcher(paths, dirs, testDebounce, func() error {
		h.calls.Add(1)
		return nil
	}, slog.Default())
	h.w = w
	w.syncDirs(h.fs)
	w.resolveTargets()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = w.loop(ctx, h.fs, h.events, make(chan error)) }()
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

func TestWatcherUnrelatedWritesDoNotPostponeReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeFile(t, path, "outputs: {}")
	synctest.Test(t, func(t *testing.T) {
		h, cancel := runLoop(t, []string{path})
		defer cancel()

		h.events <- fsnotify.Event{Name: path, Op: fsnotify.Write}
		for range 10 {
			time.Sleep(testDebounce / 2)
			h.events <- fsnotify.Event{Name: filepath.Join(dir, "app.log"), Op: fsnotify.Write}
		}
		synctest.Wait()
		assert.Equal(t, int64(1), h.calls.Load(), "the reload fires one debounce after the config write")
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
