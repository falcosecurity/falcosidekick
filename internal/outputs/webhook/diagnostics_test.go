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

package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func TestConstructorErrorsNameFieldWithoutValue(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	tests := []struct {
		config map[string]any
		name   string
		want   string
	}{
		{
			name:   "malformed url",
			config: map[string]any{"host": "https://u:" + sentinel + "@ho st/x"},
			want:   "host: invalid URL",
		},
		{
			name:   "unsupported scheme",
			config: map[string]any{"host": "ftp://u:" + sentinel + "@host/x"},
			want:   "host: scheme must be http or https",
		},
		{
			name:   "wrong password type",
			config: map[string]any{"host": "https://h/x", "password": map[string]any{"a": sentinel}},
			want:   "password: invalid type, expected string",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := OutputType.New(tc.config, output.Deps{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Contains(t, err.Error(), "webhook")
			assert.NotContains(t, err.Error(), sentinel)
		})
	}
}
