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

package database

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// Memory is an in-memory core.Database; UI-only entries do not survive a restart.
type Memory struct {
	outputs map[string]*core.OutputConfigEntry
	layout  *core.PipelineLayout
	// lastOutputVersion numbers output writes store-wide, so an output deleted and created
	// again never repeats a version a client still holds.
	lastOutputVersion int64
	mu                sync.RWMutex
}

// NewMemory creates a memory-backed Database.
func NewMemory() *Memory {
	return &Memory{
		outputs: make(map[string]*core.OutputConfigEntry),
	}
}

// Provision upserts file-sourced configs and removes stale provisioned entries.
func (s *Memory) Provision(_ context.Context, req *core.ProvisionRequest) error {
	if req == nil {
		return fmt.Errorf("database: provision request is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	for name, entry := range s.outputs {
		if entry.Provisioned {
			if _, exists := req.Outputs[name]; !exists {
				delete(s.outputs, name)
			}
		}
	}

	for name, cfg := range req.Outputs {
		// An unchanged output keeps its version, so a client editing it is not refused for nothing.
		if existing := s.outputs[name]; existing != nil && existing.Provisioned && sameConfig(existing.Config, cfg) {
			continue
		}
		s.lastOutputVersion++
		s.outputs[name] = &core.OutputConfigEntry{
			Name:        name,
			Config:      utils.DeepCopyMap(cfg),
			Version:     s.lastOutputVersion,
			Provisioned: true,
			UpdatedAt:   now,
		}
	}

	return nil
}

// GetOutputConfigs returns a defensive copy of all output entries.
func (s *Memory) GetOutputConfigs(_ context.Context) (map[string]*core.OutputConfigEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*core.OutputConfigEntry, len(s.outputs))
	for k, v := range s.outputs {
		result[k] = v.DeepCopy()
	}
	return result, nil
}

// GetOutputConfig returns the named entry, or nil and no error when it does not exist.
func (s *Memory) GetOutputConfig(_ context.Context, name string) (*core.OutputConfigEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.outputs[name]
	if !ok {
		return nil, nil
	}
	return entry.DeepCopy(), nil
}

// SaveOutputConfig stores the config if the stored version is expected, keeping the Provisioned flag.
func (s *Memory) SaveOutputConfig(_ context.Context, name string, expected int64, cfg map[string]any) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.outputs[name]
	if storedVersion(existing) != expected {
		return 0, core.ErrVersionConflict
	}
	var provisioned bool
	if existing != nil {
		provisioned = existing.Provisioned
	}
	s.lastOutputVersion++
	s.outputs[name] = &core.OutputConfigEntry{
		Name:        name,
		Config:      utils.DeepCopyMap(cfg),
		Version:     s.lastOutputVersion,
		Provisioned: provisioned,
		UpdatedAt:   time.Now(),
	}
	return s.lastOutputVersion, nil
}

// DeleteOutputConfig removes the entry if its version is expected.
func (s *Memory) DeleteOutputConfig(_ context.Context, name string, expected int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if storedVersion(s.outputs[name]) != expected {
		return core.ErrVersionConflict
	}
	delete(s.outputs, name)
	return nil
}

func storedVersion(entry *core.OutputConfigEntry) int64 {
	if entry == nil {
		return 0
	}
	return entry.Version
}

// GetPipelineLayout returns the stored pipeline layout or nil.
func (s *Memory) GetPipelineLayout(_ context.Context) (*core.PipelineLayout, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.layout == nil {
		return nil, nil
	}
	return s.layout.DeepCopy(), nil
}

// SavePipelineLayout persists the UI pipeline node positions.
func (s *Memory) SavePipelineLayout(_ context.Context, layout *core.PipelineLayout) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := layout.DeepCopy()
	cp.UpdatedAt = time.Now()
	s.layout = cp
	return nil
}

// Close releases resources. No-op for the memory backend.
func (s *Memory) Close() error {
	return nil
}
