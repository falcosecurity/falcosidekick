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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSameConfig(t *testing.T) {
	tests := []struct {
		a, b map[string]any
		name string
		same bool
	}{
		{name: "yaml int and json float", a: map[string]any{"port": 5}, b: map[string]any{"port": 5.0}, same: true},
		{name: "typed and generic maps", a: map[string]any{"h": map[string]string{"k": "v"}}, b: map[string]any{"h": map[string]any{"k": "v"}}, same: true},
		{name: "typed and generic lists", a: map[string]any{"l": []string{"a"}}, b: map[string]any{"l": []any{"a"}}, same: true},
		{name: "changed value", a: map[string]any{"port": 5}, b: map[string]any{"port": 6}},
		{name: "added key", a: map[string]any{"port": 5}, b: map[string]any{"port": 5, "host": "h"}},
		{name: "empty and nil", a: map[string]any{}, b: nil},
		{name: "unmarshalable", a: map[string]any{"f": func() {}}, b: map[string]any{"f": func() {}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.same, sameConfig(tt.a, tt.b))
		})
	}
}
