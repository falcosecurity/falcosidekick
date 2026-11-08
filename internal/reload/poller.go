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

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// Poller compares content hashes of output config files and secret files to catch changes fsnotify misses.
type Poller struct {
	reloadFn func() error
	files    func() []string
	hashes   map[string][sha256.Size]byte
	logger   *slog.Logger
	paths    []string
	interval time.Duration
}

// NewPoller creates a content-hash poller for the given output config paths and, when files is not
// nil, for the secret files it returns at each tick. A secret file seen for the first time after
// the first tick counts as a change.
func NewPoller(paths []string, files func() []string, interval time.Duration, reloadFn func() error, logger *slog.Logger) *Poller {
	return &Poller{
		paths:    paths,
		files:    files,
		interval: interval,
		reloadFn: reloadFn,
		hashes:   make(map[string][sha256.Size]byte),
		logger:   logger,
	}
}

// Run polls until ctx is canceled; the first tick only records hashes.
func (p *Poller) Run(ctx context.Context) error {
	for _, path := range p.paths {
		h, err := hashFile(path)
		if err != nil {
			p.logger.Warn("poller: initial hash failed", "path", path, "error", err)
			continue
		}
		p.hashes[path] = h
	}
	for _, path := range p.secretFiles() {
		if h, err := hashSecretFile(path); err == nil {
			p.hashes[path] = h
		}
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if p.checkForChanges() {
				p.logger.Info("output config or secret content changed (poll), reloading")
				if err := p.reloadFn(); err != nil {
					p.logger.Error("reload failed (poll)", "error", err)
				}
			}
		}
	}
}

func (p *Poller) checkForChanges() bool {
	changed := false
	seen := make(map[string]bool, len(p.hashes))
	for _, path := range p.paths {
		seen[path] = true
		h, err := hashFile(path)
		if err != nil {
			p.logger.Warn("poller: hash failed", "path", path, "error", err)
			continue
		}
		changed = p.record(path, h) || changed
	}
	for _, path := range p.secretFiles() {
		if seen[path] {
			continue
		}
		seen[path] = true
		h, err := hashSecretFile(path)
		if err != nil {
			p.logger.Debug("poller: secret hash failed", "path", path, "error", err)
			continue
		}
		changed = p.record(path, h) || changed
	}
	// A file no longer listed is forgotten, so it counts as new if it comes back.
	for path := range p.hashes {
		if !seen[path] {
			delete(p.hashes, path)
		}
	}
	return changed
}

// record stores h for path and reports whether it differs from the stored one.
func (p *Poller) record(path string, h [sha256.Size]byte) bool {
	if prev, ok := p.hashes[path]; ok && prev == h {
		return false
	}
	p.hashes[path] = h
	return true
}

func (p *Poller) secretFiles() []string {
	if p.files == nil {
		return nil
	}
	return p.files()
}

func hashFile(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided config file path
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// hashSecretFile reads like the secret resolution does, so a FIFO or an oversized file is refused.
func hashSecretFile(path string) ([sha256.Size]byte, error) {
	data, err := utils.ReadRegularFile(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}
