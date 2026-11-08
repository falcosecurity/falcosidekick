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

package testutil

import (
	"context"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

// Mock is a core.Database test double. Reads return the matching state
// field; writes are no-ops; non-nil *Err fields short-circuit the
// matching method with that error.
type Mock struct {
	Outputs    map[string]*core.OutputConfigEntry
	CoreConfig *core.ConfigEntry
	Layout     *core.PipelineLayout

	ProvisionErr          error
	GetConfigErr          error
	SaveConfigErr         error
	GetOutputConfigsErr   error
	GetOutputConfigErr    error
	SaveOutputConfigErr   error
	DeleteOutputConfigErr error
	GetPipelineLayoutErr  error
	SavePipelineLayoutErr error
	CloseErr              error
}

// Provision returns ProvisionErr.
func (m *Mock) Provision(_ context.Context, _ *core.ProvisionRequest) error {
	return m.ProvisionErr
}

// GetConfig returns CoreConfig and GetConfigErr.
func (m *Mock) GetConfig(_ context.Context) (*core.ConfigEntry, error) {
	return m.CoreConfig, m.GetConfigErr
}

// SaveConfig returns SaveConfigErr.
func (m *Mock) SaveConfig(_ context.Context, _ *core.Config) error {
	return m.SaveConfigErr
}

// GetOutputConfigs returns Outputs and GetOutputConfigsErr.
func (m *Mock) GetOutputConfigs(_ context.Context) (map[string]*core.OutputConfigEntry, error) {
	return m.Outputs, m.GetOutputConfigsErr
}

// GetOutputConfig returns GetOutputConfigErr when set, otherwise the
// entry from Outputs (or nil, nil on miss).
func (m *Mock) GetOutputConfig(_ context.Context, name string) (*core.OutputConfigEntry, error) {
	if m.GetOutputConfigErr != nil {
		return nil, m.GetOutputConfigErr
	}
	entry, ok := m.Outputs[name]
	if !ok {
		return nil, nil
	}
	return entry, nil
}

// SaveOutputConfig returns SaveOutputConfigErr.
func (m *Mock) SaveOutputConfig(_ context.Context, _ string, _ map[string]any) error {
	return m.SaveOutputConfigErr
}

// DeleteOutputConfig returns DeleteOutputConfigErr.
func (m *Mock) DeleteOutputConfig(_ context.Context, _ string) error {
	return m.DeleteOutputConfigErr
}

// GetPipelineLayout returns Layout and GetPipelineLayoutErr.
func (m *Mock) GetPipelineLayout(_ context.Context) (*core.PipelineLayout, error) {
	return m.Layout, m.GetPipelineLayoutErr
}

// SavePipelineLayout returns SavePipelineLayoutErr.
func (m *Mock) SavePipelineLayout(_ context.Context, _ *core.PipelineLayout) error {
	return m.SavePipelineLayoutErr
}

// Close returns CloseErr.
func (m *Mock) Close() error {
	return m.CloseErr
}
