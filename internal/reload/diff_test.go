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

package reload

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiffOutputConfigsAddOnly(t *testing.T) {
	old := map[string]map[string]any{}
	updated := map[string]map[string]any{
		"slack": {"secret_endpoint": "https://hooks.slack.com/test"},
	}

	diff := DiffOutputConfigs(old, updated)

	assert.Len(t, diff.Added, 1)
	assert.Contains(t, diff.Added, "slack")
	assert.Empty(t, diff.Changed)
	assert.Empty(t, diff.Removed)
	assert.False(t, diff.IsEmpty())
}

func TestDiffOutputConfigsRemoveOnly(t *testing.T) {
	old := map[string]map[string]any{
		"slack": {"secret_endpoint": "https://hooks.slack.com/test"},
	}
	updated := map[string]map[string]any{}

	diff := DiffOutputConfigs(old, updated)

	assert.Empty(t, diff.Added)
	assert.Empty(t, diff.Changed)
	assert.Equal(t, []string{"slack"}, diff.Removed)
	assert.False(t, diff.IsEmpty())
}

func TestDiffOutputConfigsChangeOnly(t *testing.T) {
	old := map[string]map[string]any{
		"slack": {"secret_endpoint": "https://hooks.slack.com/old"},
	}
	updated := map[string]map[string]any{
		"slack": {"secret_endpoint": "https://hooks.slack.com/new"},
	}

	diff := DiffOutputConfigs(old, updated)

	assert.Empty(t, diff.Added)
	assert.Len(t, diff.Changed, 1)
	assert.Contains(t, diff.Changed, "slack")
	assert.Empty(t, diff.Removed)
}

func TestDiffOutputConfigsNoChange(t *testing.T) {
	cfg := map[string]map[string]any{
		"slack": {"secret_endpoint": "https://hooks.slack.com/same"},
		"loki":  {"host": "http://loki:3100"},
	}

	diff := DiffOutputConfigs(cfg, cfg)

	assert.True(t, diff.IsEmpty())
}

func TestDiffOutputConfigsMixed(t *testing.T) {
	old := map[string]map[string]any{
		"slack": {"secret_endpoint": "https://hooks.slack.com/old"},
		"loki":  {"host": "http://loki:3100"},
	}
	updated := map[string]map[string]any{
		"slack":         {"secret_endpoint": "https://hooks.slack.com/new"},
		"elasticsearch": {"host": "https://es:9200"},
	}

	diff := DiffOutputConfigs(old, updated)

	assert.Len(t, diff.Added, 1)
	assert.Contains(t, diff.Added, "elasticsearch")
	assert.Len(t, diff.Changed, 1)
	assert.Contains(t, diff.Changed, "slack")
	assert.Equal(t, []string{"loki"}, diff.Removed)
}

func TestDiffOutputConfigsNestedMapChange(t *testing.T) {
	old := map[string]map[string]any{
		"es": {"tls": map[string]any{"ca_file": "/old/ca.crt"}},
	}
	updated := map[string]map[string]any{
		"es": {"tls": map[string]any{"ca_file": "/new/ca.crt"}},
	}

	diff := DiffOutputConfigs(old, updated)

	assert.Len(t, diff.Changed, 1)
	assert.Contains(t, diff.Changed, "es")
}

func TestDiffOutputConfigsNestedMapNoChange(t *testing.T) {
	cfg := map[string]map[string]any{
		"es": {"tls": map[string]any{"ca_file": "/same/ca.crt", "enabled": true}},
	}

	diff := DiffOutputConfigs(cfg, cfg)

	assert.True(t, diff.IsEmpty())
}

func TestDiffOutputConfigsEmptyInputs(t *testing.T) {
	diff := DiffOutputConfigs(nil, nil)
	assert.True(t, diff.IsEmpty())
}

func TestDiffOutputConfigsBothEmpty(t *testing.T) {
	old := map[string]map[string]any{}
	updated := map[string]map[string]any{}

	diff := DiffOutputConfigs(old, updated)
	assert.True(t, diff.IsEmpty())
}
