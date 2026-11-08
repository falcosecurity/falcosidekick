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

package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortMapKeys(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		want []string
	}{
		{"sorted output", map[string]any{"z": 1, "a": 2, "m": 3}, []string{"a", "m", "z"}},
		{"single key", map[string]any{"only": 1}, []string{"only"}},
		{"empty map", map[string]any{}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SortMapKeys(tt.m))
		})
	}
}

func TestSortMapKeysNilMap(t *testing.T) {
	var m map[string]string
	keys := SortMapKeys(m)
	assert.Empty(t, keys)
}

func TestFormatTags(t *testing.T) {
	tests := []struct {
		name string
		sep  string
		want string
		tags []string
	}{
		{name: "sorts and joins", tags: []string{"z", "a", "m"}, sep: ", ", want: "a, m, z"},
		{name: "comma separator", tags: []string{"b", "a"}, sep: ",", want: "a,b"},
		{name: "single tag", tags: []string{"only"}, sep: ", ", want: "only"},
		{name: "empty slice", tags: []string{}, sep: ", ", want: ""},
		{name: "nil slice", tags: nil, sep: ", ", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FormatTags(tt.tags, tt.sep))
		})
	}
}

func TestTruncateRunes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		max   int
	}{
		{name: "no truncation needed", input: "short", max: 10, want: "short"},
		{name: "exact length", input: "exact", max: 5, want: "exact"},
		{name: "truncated with ellipsis", input: "this is a long string", max: 10, want: "this is..."},
		{name: "unicode runes", input: "hello\u2603world", max: 7, want: "hell..."},
		{name: "very small max", input: "abcdefg", max: 3, want: "abc"},
		{name: "empty string", input: "", max: 10, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, TruncateRunes(tt.input, tt.max))
		})
	}
}

func TestFormatTagsDoesNotMutateInput(t *testing.T) {
	input := []string{"z", "a", "m"}
	_ = FormatTags(input, ",")
	assert.Equal(t, []string{"z", "a", "m"}, input, "input slice must not be mutated")
}
