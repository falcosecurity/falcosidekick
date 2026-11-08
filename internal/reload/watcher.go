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
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher monitors output config files via fsnotify and triggers reload
// on Write, Create, or Rename events. Parent directories are watched
// instead of files directly so that atomic-save patterns (write-temp +
// rename) are detected even when the file inode changes. A debounce
// timer coalesces rapid events into a single reload call.
type Watcher struct {
	reloadFn  func() error
	logger    *slog.Logger
	filenames map[string]bool
	paths     []string
	debounce  time.Duration
}

// NewWatcher creates a file watcher for the given output config paths.
func NewWatcher(paths []string, debounce time.Duration, reloadFn func() error, logger *slog.Logger) *Watcher {
	names := make(map[string]bool, len(paths))
	for _, p := range paths {
		names[filepath.Base(p)] = true
	}
	return &Watcher{
		paths:     paths,
		filenames: names,
		reloadFn:  reloadFn,
		debounce:  debounce,
		logger:    logger,
	}
}

// Run starts the fsnotify event loop. Blocks until ctx is canceled or
// the watcher encounters a fatal error.
func (w *Watcher) Run(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() { _ = fsw.Close() }()

	dirs := parentDirs(w.paths)
	for _, d := range dirs {
		if err := fsw.Add(d); err != nil {
			return err
		}
	}

	var timer *time.Timer
	var timerC <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()

		case ev, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if !isReloadEvent(ev.Op) {
				continue
			}
			if !w.filenames[filepath.Base(ev.Name)] {
				continue
			}
			if timer == nil {
				timer = time.NewTimer(w.debounce)
				timerC = timer.C
			} else {
				timer.Reset(w.debounce)
			}

		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			w.logger.Error("fsnotify error", "error", err)

		case <-timerC:
			w.logger.Info("output config file changed, reloading")
			if err := w.reloadFn(); err != nil {
				w.logger.Error("reload failed", "error", err)
			}
			timer = nil
			timerC = nil
		}
	}
}

func isReloadEvent(op fsnotify.Op) bool {
	return op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0
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
