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

// Watcher triggers a debounced reload when fsnotify reports an output config change.
// It watches parent directories so atomic renames and ConfigMap ..data swaps are seen.
type Watcher struct {
	reloadFn func() error
	logger   *slog.Logger
	ready    chan struct{}
	// targets holds each path's resolved symlink target; owned by the Run goroutine.
	targets  map[string]string
	paths    []string
	debounce time.Duration
}

// NewWatcher creates a file watcher for the given output config paths.
func NewWatcher(paths []string, debounce time.Duration, reloadFn func() error, logger *slog.Logger) *Watcher {
	cleaned := make([]string, len(paths))
	for i, p := range paths {
		cleaned[i] = filepath.Clean(p)
	}
	return &Watcher{
		paths:    cleaned,
		targets:  make(map[string]string, len(paths)),
		reloadFn: reloadFn,
		debounce: debounce,
		logger:   logger,
		ready:    make(chan struct{}),
	}
}

// Ready is closed once every parent directory is watched; earlier changes are missed.
func (w *Watcher) Ready() <-chan struct{} { return w.ready }

// Run watches until ctx is canceled or fsnotify fails.
func (w *Watcher) Run(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() { _ = fsw.Close() }()

	for _, d := range parentDirs(w.paths) {
		if err := fsw.Add(d); err != nil {
			return err
		}
	}
	w.resolveTargets()
	close(w.ready)
	return w.loop(ctx, fsw.Events, fsw.Errors)
}

// loop compares symlink targets when the debounce fires, not on each event: kqueue
// reports no event for a rename over an existing entry such as the ConfigMap ..data swap.
func (w *Watcher) loop(ctx context.Context, events <-chan fsnotify.Event, errs <-chan error) error {
	var timer *time.Timer
	var timerC <-chan time.Time
	direct := false

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
			direct = direct || ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 &&
				slices.Contains(w.paths, filepath.Clean(ev.Name))
			if timer == nil {
				timer = time.NewTimer(w.debounce)
				timerC = timer.C
			} else {
				timer.Reset(w.debounce)
			}

		case err, ok := <-errs:
			if !ok {
				return nil
			}
			w.logger.Error("fsnotify error", "error", err)

		case <-timerC:
			if w.resolveTargets() || direct {
				w.logger.Info("output config file changed, reloading")
				if err := w.reloadFn(); err != nil {
					w.logger.Error("reload failed", "error", err)
				}
			}
			direct = false
			timer = nil
			timerC = nil
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
