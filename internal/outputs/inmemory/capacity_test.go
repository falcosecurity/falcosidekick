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

package inmemory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// The ring is allocated in full by the constructor, so the bound is checked first.
func TestCapacityBounds(t *testing.T) {
	cat, err := catalog.New([]output.Type{OutputType})
	require.NoError(t, err)
	const refused = `catalog: create "inmemory": inmemory config: capacity: must be an integer between 1 and 100000`
	for _, tt := range []struct {
		value any
		name  string
		want  string
		size  int
	}{
		{name: "omitted takes the default", size: defaultCapacity},
		{name: "null takes the default", value: nil, size: defaultCapacity},
		{name: "explicit zero", value: 0, want: refused},
		{name: "min", value: 1, size: 1},
		{name: "max", value: 100_000, size: 100_000},
		{name: "above max", value: 100_001, want: refused},
		{name: "negative", value: -1, want: refused},
		{name: "beyond int64", value: 1e20, want: `catalog: create "inmemory": inmemory config: capacity: is out of range`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := map[string]any{}
			if tt.name != "omitted takes the default" {
				raw["capacity"] = tt.value
			}
			created, err := cat.Create(name, raw, output.Deps{})
			if tt.want != "" {
				require.EqualError(t, err, tt.want)
				return
			}
			require.NoError(t, err)
			assert.Len(t, created.(*driver).events, tt.size)
		})
	}
}

func TestCapacityBoundWithoutTheCatalog(t *testing.T) {
	_, err := OutputType.New(map[string]any{"capacity": 100_001}, output.Deps{})
	require.EqualError(t, err, "inmemory: capacity: must be an integer between 1 and 100000")
}
