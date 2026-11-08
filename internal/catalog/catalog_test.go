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

package catalog

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func stubType(name, category string) output.Type {
	return output.Type{
		Name:     name,
		Category: category,
		Schema:   output.Schema{},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: name}, nil
		},
	}
}

func failingType(name string) output.Type {
	return output.Type{
		Name:     name,
		Category: "test",
		Schema:   output.Schema{},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return nil, fmt.Errorf("constructor failed")
		},
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		types   []output.Type
		wantErr bool
	}{
		{
			name:  "valid single type",
			types: []output.Type{stubType("slack", "chat")},
		},
		{
			name:  "valid multiple types",
			types: []output.Type{stubType("slack", "chat"), stubType("loki", "logs")},
		},
		{
			name:    "empty list",
			types:   []output.Type{},
			wantErr: true,
			errMsg:  "at least one",
		},
		{
			name:    "nil list",
			types:   nil,
			wantErr: true,
			errMsg:  "at least one",
		},
		{
			name: "duplicate name",
			types: []output.Type{
				stubType("slack", "chat"),
				stubType("slack", "chat"),
			},
			wantErr: true,
			errMsg:  "duplicate",
		},
		{
			name: "empty name",
			types: []output.Type{
				{Name: "", Category: "test", New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
					return &testutil.MockDriver{}, nil
				}},
			},
			wantErr: true,
			errMsg:  "empty name",
		},
		{
			name: "nil constructor",
			types: []output.Type{
				{Name: "broken", Category: "test", New: nil},
			},
			wantErr: true,
			errMsg:  "nil constructor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cat, err := New(tt.types)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, cat)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cat)
		})
	}
}

func TestGet(t *testing.T) {
	cat, err := New([]output.Type{
		stubType("slack", "chat"),
		stubType("webhook", "webhook"),
	})
	require.NoError(t, err)

	tests := []struct {
		name  string
		found bool
	}{
		{"slack", true},
		{"webhook", true},
		{"nonexistent", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ot, ok := cat.Get(tt.name)
			assert.Equal(t, tt.found, ok)
			if tt.found {
				assert.Equal(t, tt.name, ot.Name)
			}
		})
	}
}

func TestAll(t *testing.T) {
	cat, err := New([]output.Type{
		stubType("slack", "chat"),
		stubType("loki", "logs"),
		stubType("webhook", "webhook"),
	})
	require.NoError(t, err)

	all := cat.All()
	assert.Len(t, all, 3)

	names := make(map[string]bool)
	for _, t := range all {
		names[t.Name] = true
	}
	assert.True(t, names["slack"])
	assert.True(t, names["loki"])
	assert.True(t, names["webhook"])
}

func TestAllReturnsCopy(t *testing.T) {
	cat, err := New([]output.Type{stubType("slack", "chat")})
	require.NoError(t, err)

	all := cat.All()
	all[0] = output.Type{Name: "mutated"}

	original, ok := cat.Get("slack")
	assert.True(t, ok)
	assert.Equal(t, "slack", original.Name, "mutating All() result must not affect catalog")
}

func TestCreate(t *testing.T) {
	cat, err := New([]output.Type{
		stubType("slack", "chat"),
		failingType("broken"),
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		output  string
		errMsg  string
		wantErr bool
	}{
		{name: "existing type", output: "slack"},
		{name: "unknown type", output: "nonexistent", wantErr: true, errMsg: "unknown"},
		{name: "failing constructor", output: "broken", wantErr: true, errMsg: "constructor failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := cat.Create(tt.output, nil, output.Deps{})
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.output, driver.Name())
		})
	}
}

func TestNames(t *testing.T) {
	cat, err := New([]output.Type{
		stubType("webhook", "webhook"),
		stubType("slack", "chat"),
	})
	require.NoError(t, err)

	names := cat.Names()
	assert.Len(t, names, 2)
	assert.Contains(t, names, "slack")
	assert.Contains(t, names, "webhook")
}
