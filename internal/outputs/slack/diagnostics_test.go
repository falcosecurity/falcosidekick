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

package slack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func TestConstructorErrorsNeverExposeWebhookURL(t *testing.T) {
	const sentinel = "T000/B000/s3cret-sentinel"
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "malformed", value: "https://hooks.slack.com:bad/services/" + sentinel, want: "host: invalid URL"},
		{name: "missing scheme", value: "hooks.slack.com/services/" + sentinel, want: "host: must include scheme and host"},
		{name: "unsupported scheme", value: "ftp://hooks.slack.com/services/" + sentinel, want: "host: scheme must be http or https"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := OutputType.New(map[string]any{"host": tc.value, "secret_endpoint": "/services/x"}, output.Deps{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), sentinel)
		})
	}
}
