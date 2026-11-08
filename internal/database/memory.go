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

// Memory implements domain.Database with in-memory maps.
// All data is lost on restart and re-provisioned from files.
type Memory struct {
	outputs    map[string]*core.OutputConfigEntry
	coreConfig *core.ConfigEntry
	layout     *core.PipelineLayout
	mu         sync.RWMutex
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

	if req.Config != nil {
		s.coreConfig = &core.ConfigEntry{
			Config:    req.Config.DeepCopy(),
			Version:   nextVersion(s.coreConfig),
			UpdatedAt: now,
		}
	}

	if !req.DisableDeletion {
		for name, entry := range s.outputs {
			if entry.Provisioned {
				if _, exists := req.Outputs[name]; !exists {
					delete(s.outputs, name)
				}
			}
		}
	}

	for name, cfg := range req.Outputs {
		s.outputs[name] = &core.OutputConfigEntry{
			Name:        name,
			Config:      utils.DeepCopyMap(cfg),
			Version:     nextVersion(s.outputs[name]),
			Provisioned: true,
			UpdatedAt:   now,
		}
	}

	return nil
}

// GetConfig returns the stored core configuration.
func (s *Memory) GetConfig(_ context.Context) (*core.ConfigEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.coreConfig == nil {
		return nil, nil
	}
	return s.coreConfig.DeepCopy(), nil
}

// SaveConfig persists the core configuration.
func (s *Memory) SaveConfig(_ context.Context, cfg *core.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.coreConfig = &core.ConfigEntry{
		Config:    cfg.DeepCopy(),
		Version:   nextVersion(s.coreConfig),
		UpdatedAt: time.Now(),
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

// GetOutputConfig returns a single output entry by name. Returns
// (nil, nil) when the named output does not exist; any error indicates
// a backend failure.
func (s *Memory) GetOutputConfig(_ context.Context, name string) (*core.OutputConfigEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.outputs[name]
	if !ok {
		return nil, nil
	}
	return entry.DeepCopy(), nil
}

// SaveOutputConfig stores the config. Existing entries preserve the
// Provisioned flag and bump Version; new entries start as Provisioned:false.
func (s *Memory) SaveOutputConfig(_ context.Context, name string, cfg map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.outputs[name]
	var provisioned bool
	if existing != nil {
		provisioned = existing.Provisioned
	}
	s.outputs[name] = &core.OutputConfigEntry{
		Name:        name,
		Config:      utils.DeepCopyMap(cfg),
		Version:     nextVersion(existing),
		Provisioned: provisioned,
		UpdatedAt:   time.Now(),
	}
	return nil
}

// DeleteOutputConfig removes one output entry. A miss returns nil; any
// error return indicates a real backend failure.
func (s *Memory) DeleteOutputConfig(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.outputs, name)
	return nil
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
