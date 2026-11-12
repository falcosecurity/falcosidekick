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

func stubType(name string, category output.Category) output.Type {
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
		Category: output.CategoryOther,
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
		{
			name:    "unknown category",
			types:   []output.Type{stubType("syslog", "logging")},
			wantErr: true,
			errMsg:  `unknown category "logging"`,
		},
		{
			name:  "no category, as test doubles leave it",
			types: []output.Type{stubType("noop", "")},
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

// Normalization runs on a copy; the caller's config is unchanged.
func TestCreateNormalizesBeforeTheConstructor(t *testing.T) {
	var received map[string]any
	calls := 0
	typ := output.Type{
		Name: "probe",
		Schema: output.Schema{Fields: []output.SchemaField{
			{Name: "mode", Type: "enum", Values: []string{"a", "b"}, Default: "a"},
			output.SchemaField{Name: "runtime.queue_size", Type: "int", Default: 1000}.WithIntRange(output.QueueSizeRange),
		}},
		New: func(raw map[string]any, _ output.Deps) (output.Driver, error) {
			calls++
			received = raw
			return &testutil.MockDriver{DriverName: "probe"}, nil
		},
	}
	cat, err := New([]output.Type{typ})
	require.NoError(t, err)

	written := map[string]any{"mode": "", "token": nil, "runtime": map[string]any{"queue_size": 100_000}}
	_, err = cat.Create("probe", written, output.Deps{})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"token": nil, "runtime": map[string]any{"queue_size": 100_000}}, received,
		"a null is left for the decoder, which refuses it under an unknown key")
	assert.Equal(t, map[string]any{"mode": "", "token": nil, "runtime": map[string]any{"queue_size": 100_000}}, written,
		"the caller keeps the config as written")

	for _, tt := range []struct {
		value any
		want  string
	}{
		{0, `catalog: create "probe": probe config: runtime.queue_size: must be an integer between 1 and 100000`},
		{100_001, `catalog: create "probe": probe config: runtime.queue_size: must be an integer between 1 and 100000`},
		{1e20, `catalog: create "probe": probe config: runtime.queue_size: is out of range`},
	} {
		calls = 0
		_, err = cat.Create("probe", map[string]any{"runtime": map[string]any{"queue_size": tt.value}}, output.Deps{})
		require.EqualError(t, err, tt.want)
		assert.Zero(t, calls, "nothing is built for a value out of range")
	}
}
