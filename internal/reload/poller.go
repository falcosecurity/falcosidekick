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
	"crypto/sha256"
	"log/slog"
	"os"
	"time"
)

// Poller periodically compares SHA-256 content hashes of output config files
// to detect changes that fsnotify may miss (e.g., K8s ConfigMap symlink swaps).
type Poller struct {
	reloadFn func() error
	hashes   map[string][sha256.Size]byte
	logger   *slog.Logger
	paths    []string
	interval time.Duration
}

// NewPoller creates a content-hash poller for the given output config paths.
func NewPoller(paths []string, interval time.Duration, reloadFn func() error, logger *slog.Logger) *Poller {
	return &Poller{
		paths:    paths,
		interval: interval,
		reloadFn: reloadFn,
		hashes:   make(map[string][sha256.Size]byte),
		logger:   logger,
	}
}

// Run starts the polling loop. Blocks until ctx is canceled. On the first
// tick, computes initial hashes without triggering a reload.
func (p *Poller) Run(ctx context.Context) error {
	for _, path := range p.paths {
		h, err := hashFile(path)
		if err != nil {
			p.logger.Warn("poller: initial hash failed", "path", path, "error", err)
			continue
		}
		p.hashes[path] = h
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if p.checkForChanges() {
				p.logger.Info("output config content changed (poll), reloading")
				if err := p.reloadFn(); err != nil {
					p.logger.Error("reload failed (poll)", "error", err)
				}
			}
		}
	}
}

func (p *Poller) checkForChanges() bool {
	changed := false
	for _, path := range p.paths {
		h, err := hashFile(path)
		if err != nil {
			p.logger.Warn("poller: hash failed", "path", path, "error", err)
			continue
		}
		if prev, ok := p.hashes[path]; !ok || prev != h {
			p.hashes[path] = h
			changed = true
		}
	}
	return changed
}

func hashFile(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided config file path
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}
