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
	"path/filepath"
	"slices"
	"time"

	"github.com/fsnotify/fsnotify"
)

// dirWatcher is the part of fsnotify.Watcher the loop uses to change the watched directories.
type dirWatcher interface {
	Add(name string) error
	Remove(name string) error
}

// Watcher triggers a debounced reload when fsnotify reports an output config change or any change
// in a secret directory. It watches parent directories so atomic renames and ..data swaps are seen.
type Watcher struct {
	notify  func()
	dirs    func() []string
	logger  *slog.Logger
	ready   chan struct{}
	refresh chan struct{}
	// targets, watched, secretDirs and failed are owned by the Run goroutine.
	targets    map[string]string
	watched    map[string]bool
	secretDirs map[string]bool
	failed     map[string]bool
	paths      []string
	configDirs []string
	debounce   time.Duration
}

// NewWatcher creates a watcher for the given output config paths and, when dirs is not nil, for
// the secret directories it returns. dirs is called again after each debounced reload and on Refresh.
func NewWatcher(paths []string, dirs func() []string, debounce time.Duration, notify func(), logger *slog.Logger) *Watcher {
	cleaned := make([]string, len(paths))
	for i, p := range paths {
		cleaned[i] = filepath.Clean(p)
	}
	return &Watcher{
		paths:      cleaned,
		configDirs: parentDirs(cleaned),
		dirs:       dirs,
		targets:    make(map[string]string, len(paths)),
		watched:    make(map[string]bool),
		secretDirs: make(map[string]bool),
		failed:     make(map[string]bool),
		notify:     notify,
		debounce:   debounce,
		logger:     logger,
		ready:      make(chan struct{}),
		refresh:    make(chan struct{}, 1),
	}
}

// Ready is closed once every directory is watched; earlier changes are missed.
func (w *Watcher) Ready() <-chan struct{} { return w.ready }

// Refresh asks Run to watch the secret directories dirs returns now. It never blocks.
func (w *Watcher) Refresh() {
	select {
	case w.refresh <- struct{}{}:
	default:
	}
}

// Run watches until ctx is canceled or fsnotify fails. A config directory that cannot be watched
// fails Run; a secret directory that cannot be watched is logged and tried again at the next sync.
func (w *Watcher) Run(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() { _ = fsw.Close() }()

	for _, d := range w.configDirs {
		if err := fsw.Add(d); err != nil {
			return err
		}
		w.watched[d] = true
	}
	w.syncDirs(fsw)
	w.resolveTargets()
	close(w.ready)
	return w.loop(ctx, fsw, fsw.Events, fsw.Errors)
}

// loop compares symlink targets when the debounce fires, not on each event: kqueue
// reports no event for a rename over an existing entry such as the ConfigMap ..data swap.
func (w *Watcher) loop(ctx context.Context, fsw dirWatcher, events <-chan fsnotify.Event, errs <-chan error) error {
	var timer *time.Timer
	var timerC <-chan time.Time
	direct := false
	secret := false

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()

		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			name := filepath.Clean(ev.Name)
			// The watch went with the directory; the next sync adds it again if it is back.
			if ev.Op&(fsnotify.Rename|fsnotify.Remove) != 0 && w.watched[name] {
				_ = fsw.Remove(name)
				delete(w.watched, name)
			}
			watched := ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 &&
				slices.Contains(w.paths, name)
			direct = direct || watched
			secret = secret || w.secretDirs[name] || w.secretDirs[filepath.Dir(name)]
			// Any event arms the timer; only a watched path postpones it, so writes to
			// other files in the directory cannot delay a reload indefinitely.
			switch {
			case timer == nil:
				timer = time.NewTimer(w.debounce)
				timerC = timer.C
			case watched:
				timer.Reset(w.debounce)
			}

		case err, ok := <-errs:
			if !ok {
				return nil
			}
			w.logger.Error("fsnotify error", "error", err)

		case <-w.refresh:
			w.syncDirs(fsw)

		case <-timerC:
			configChanged := w.resolveTargets() || direct
			if configChanged || secret {
				if configChanged {
					w.logger.Info("output config file changed, reloading")
				} else {
					w.logger.Info("secret directory changed, reloading")
				}
				w.notify()
			}
			direct = false
			secret = false
			timer = nil
			timerC = nil
			w.syncDirs(fsw)
		}
	}
}

// syncDirs watches the config directories and the secret directories dirs returns, and stops
// watching the others.
func (w *Watcher) syncDirs(fsw dirWatcher) {
	want := make(map[string]bool, len(w.configDirs))
	for _, d := range w.configDirs {
		want[d] = true
	}
	secretDirs := make(map[string]bool)
	if w.dirs != nil {
		for _, d := range w.dirs() {
			d = filepath.Clean(d)
			secretDirs[d] = true
			want[d] = true
		}
	}
	w.secretDirs = secretDirs

	for d := range want {
		if w.watched[d] {
			continue
		}
		if err := fsw.Add(d); err != nil {
			if !w.failed[d] {
				w.logger.Warn("cannot watch directory, changes in it need a SIGHUP", "dir", d, "error", err)
				w.failed[d] = true
			}
			continue
		}
		delete(w.failed, d)
		w.watched[d] = true
	}
	for d := range w.watched {
		if !want[d] {
			_ = fsw.Remove(d)
			delete(w.watched, d)
		}
	}
	for d := range w.failed {
		if !want[d] {
			delete(w.failed, d)
		}
	}
}

// resolveTargets reports whether a target changed; an unresolvable path keeps its last target.
func (w *Watcher) resolveTargets() bool {
	changed := false
	for _, p := range w.paths {
		target, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		if prev, ok := w.targets[p]; ok && prev != target {
			changed = true
		}
		w.targets[p] = target
	}
	return changed
}

func parentDirs(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	var dirs []string
	for _, p := range paths {
		d := filepath.Dir(p)
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	return dirs
}
