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

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"alphanumeric passthrough", "rule_name", "rule_name"},
		{"dots to underscores", "k8s.ns.name", "k8s_ns_name"},
		{"spaces", "my rule", "my_rule"},
		{"special chars", "k8s.ns.name!", "k8s_ns_name"},
		{"double underscores collapsed", "a__b", "a_b"},
		{"leading trailing trimmed", "_test_", "test"},
		{"digit prefix", "0field", "_0field"},
		{"brackets", "proc[0].name", "proc_0_name"},
		{"dashes", "container-id", "container_id"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SanitizeLabel(tt.input))
		})
	}
}
