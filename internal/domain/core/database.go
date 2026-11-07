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

package core

import (
	"context"
	"time"
)

// Database persists all configuration synchronously, outside the event pipeline.
type Database interface {
	// Provision upserts req.Outputs as provisioned and deletes the provisioned entries
	// missing from them; unprovisioned entries are kept.
	Provision(ctx context.Context, req *ProvisionRequest) error

	// GetOutputConfigs returns all output configurations.
	GetOutputConfigs(ctx context.Context) (map[string]*OutputConfigEntry, error)

	// GetOutputConfig returns one output configuration, or (nil, nil) on a miss;
	// an error always means a backend failure.
	GetOutputConfig(ctx context.Context, name string) (*OutputConfigEntry, error)

	// SaveOutputConfig stores cfg if the stored version is expected (0: no entry yet) and returns
	// the new version; another stored version returns ErrVersionConflict and stores nothing.
	SaveOutputConfig(ctx context.Context, name string, expected int64, cfg map[string]any) (int64, error)

	// DeleteOutputConfig removes the entry if its version is expected; with expected 0 a missing
	// entry is a no-op, any other mismatch returns ErrVersionConflict.
	DeleteOutputConfig(ctx context.Context, name string, expected int64) error

	// GetPipelineLayout returns the UI pipeline layout.
	GetPipelineLayout(ctx context.Context) (*PipelineLayout, error)

	// SavePipelineLayout persists the UI pipeline layout.
	SavePipelineLayout(ctx context.Context, layout *PipelineLayout) error

	Close() error
}

// ProvisionRequest holds the file-based config passed to Provision.
type ProvisionRequest struct {
	Outputs map[string]map[string]any
}

// OutputConfigEntry wraps an output config with metadata.
type OutputConfigEntry struct {
	UpdatedAt   time.Time      `json:"updated_at"`
	Config      map[string]any `json:"config"`
	Name        string         `json:"name"`
	Version     int64          `json:"version"`
	Provisioned bool           `json:"provisioned"`
}

// PipelineLayout holds React Flow node positions for the UI.
type PipelineLayout struct {
	UpdatedAt time.Time    `json:"updated_at"`
	Nodes     []LayoutNode `json:"nodes"`
}

// LayoutNode holds position data for one node in the pipeline editor.
type LayoutNode struct {
	ID string  `json:"id"`
	X  float64 `json:"x"`
	Y  float64 `json:"y"`
}
