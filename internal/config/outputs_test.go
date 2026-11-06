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

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

func TestLoadOutputsSingleFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(f, []byte(`
outputs:
  slack:
    secret_endpoint: "/services/xxx"
    channel: "#alerts"
  elasticsearch:
    hostport: "https://es:9200"
`), 0o600))

	cfg, err := LoadOutputs([]string{f})
	require.NoError(t, err)

	require.Len(t, cfg.Outputs, 2)
	assert.Equal(t, "/services/xxx", cfg.Outputs["slack"]["secret_endpoint"])
	assert.Equal(t, "https://es:9200", cfg.Outputs["elasticsearch"]["hostport"])
}

func TestLoadOutputsMultipleFilesMerge(t *testing.T) {
	dir := t.TempDir()

	base := filepath.Join(dir, "base.yaml")
	require.NoError(t, os.WriteFile(base, []byte(`
outputs:
  slack:
    secret_endpoint: "/services/xxx"
    channel: "#alerts"
    minimum_priority: notice
`), 0o600))

	override := filepath.Join(dir, "override.yaml")
	require.NoError(t, os.WriteFile(override, []byte(`
outputs:
  slack:
    channel: "#security"
    minimum_priority: warning
`), 0o600))

	cfg, err := LoadOutputs([]string{base, override})
	require.NoError(t, err)

	require.Len(t, cfg.Outputs, 1)
	slack := cfg.Outputs["slack"]
	assert.Equal(t, "/services/xxx", slack["secret_endpoint"], "unmodified field preserved")
	assert.Equal(t, "#security", slack["channel"], "overridden field updated")
	assert.Equal(t, "warning", slack["minimum_priority"], "overridden field updated")
}

func TestLoadOutputsDeepMergeNested(t *testing.T) {
	dir := t.TempDir()

	base := filepath.Join(dir, "base.yaml")
	require.NoError(t, os.WriteFile(base, []byte(`
outputs:
  kafka:
    brokers:
      - "kafka:9092"
    topic: falco-events
    auth:
      mechanism: plain
      username: falco
      password: secret
`), 0o600))

	override := filepath.Join(dir, "override.yaml")
	require.NoError(t, os.WriteFile(override, []byte(`
outputs:
  kafka:
    auth:
      password: new-secret
`), 0o600))

	cfg, err := LoadOutputs([]string{base, override})
	require.NoError(t, err)

	kafka := cfg.Outputs["kafka"]
	auth, ok := kafka["auth"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "new-secret", auth["password"], "nested field overridden")
	assert.Equal(t, "plain", auth["mechanism"], "nested field preserved")
	assert.Equal(t, "falco", auth["username"], "nested field preserved")
}

func TestLoadOutputsNoFiles(t *testing.T) {
	cfg, err := LoadOutputs(nil)
	require.NoError(t, err)
	assert.Empty(t, cfg.Outputs)
}

func TestLoadOutputsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.yaml")
	require.NoError(t, os.WriteFile(f, []byte(""), 0o600))

	cfg, err := LoadOutputs([]string{f})
	require.NoError(t, err)
	assert.Empty(t, cfg.Outputs)
}

func TestLoadOutputsRejectsUnknownTopLevelKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(f, []byte(`
outputs:
  webhook:
    url: "http://example.com"
global_setting: bad
`), 0o600))

	_, err := LoadOutputs([]string{f})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "global_setting")
}

func TestLoadOutputsInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(f, []byte("not: valid: yaml: {{"), 0o600))

	_, err := LoadOutputs([]string{f})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse output config")
}

func TestLoadOutputsMissingFile(t *testing.T) {
	_, err := LoadOutputs([]string{"/nonexistent/outputs.yaml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read output config")
}

func TestLoadOutputsNewOutputInLaterFile(t *testing.T) {
	dir := t.TempDir()

	base := filepath.Join(dir, "base.yaml")
	require.NoError(t, os.WriteFile(base, []byte(`
outputs:
  slack:
    secret_endpoint: "/services/xxx"
`), 0o600))

	extra := filepath.Join(dir, "extra.yaml")
	require.NoError(t, os.WriteFile(extra, []byte(`
outputs:
  elasticsearch:
    hostport: "https://es:9200"
`), 0o600))

	cfg, err := LoadOutputs([]string{base, extra})
	require.NoError(t, err)

	require.Len(t, cfg.Outputs, 2)
	assert.Contains(t, cfg.Outputs, "slack")
	assert.Contains(t, cfg.Outputs, "elasticsearch")
}

func TestDeepMerge(t *testing.T) {
	tests := []struct {
		dst  map[string]any
		src  map[string]any
		want map[string]any
		name string
	}{
		{
			name: "flat overwrite",
			dst:  map[string]any{"a": "old", "b": "keep"},
			src:  map[string]any{"a": "new"},
			want: map[string]any{"a": "new", "b": "keep"},
		},
		{
			name: "nested merge",
			dst:  map[string]any{"nested": map[string]any{"a": 1, "b": 2}},
			src:  map[string]any{"nested": map[string]any{"b": 3, "c": 4}},
			want: map[string]any{"nested": map[string]any{"a": 1, "b": 3, "c": 4}},
		},
		{
			name: "new key addition",
			dst:  map[string]any{"a": 1},
			src:  map[string]any{"b": 2},
			want: map[string]any{"a": 1, "b": 2},
		},
		{
			name: "scalar overwrites map",
			dst:  map[string]any{"a": map[string]any{"x": 1}},
			src:  map[string]any{"a": "scalar"},
			want: map[string]any{"a": "scalar"},
		},
		{
			name: "map overwrites scalar",
			dst:  map[string]any{"a": "scalar"},
			src:  map[string]any{"a": map[string]any{"x": 1}},
			want: map[string]any{"a": map[string]any{"x": 1}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			utils.DeepMergeMap(tt.dst, tt.src)
			assert.Equal(t, tt.want, tt.dst)
		})
	}
}

func TestLoadOutputsParseErrorsNeverQuoteValues(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "scalar outputs", content: "outputs: \"" + sentinel + "\"\n", want: "line 1: invalid structure"},
		{name: "scalar output", content: "outputs:\n  hook: \"" + sentinel + "\"\n", want: "line 2: invalid structure"},
		{name: "scalar document", content: sentinel + "\n", want: "line 1: invalid structure"},
		{name: "syntax error", content: "outputs:\n  hook:\n    url: \"" + sentinel + "\n", want: "line 3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outputs.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o600))

			_, err := LoadOutputs([]string{path})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "parse output config")
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), "s3cret")
		})
	}
}

func TestSafeYAMLErrorFailsClosed(t *testing.T) {
	assert.Equal(t, "yaml: invalid structure", safeYAMLError(errors.New("future text s3cret-sentinel")).Error())

	construct := &yaml.LoadErrors{Errors: []*yaml.LoadError{
		{Stage: yaml.ConstructorStage, Message: "cannot construct s3cret-sentinel", Mark: yaml.Mark{Line: 2}},
	}}
	assert.Equal(t, "yaml: line 2: invalid structure", safeYAMLError(construct).Error())

	syntax := &yaml.LoadError{Stage: yaml.ParserStage, Message: "mapping values are not allowed in this context", Mark: yaml.Mark{Line: 2}}
	assert.Equal(t, "yaml: line 2: mapping values are not allowed in this context", safeYAMLError(syntax).Error())
}
