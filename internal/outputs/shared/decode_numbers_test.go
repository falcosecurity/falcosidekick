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
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

type runtimeTarget struct {
	Name    string               `mapstructure:"name"`
	Runtime output.RuntimeConfig `mapstructure:"runtime"`
}

// The same refusals from every source: YAML, json.Number and a restored row.
func TestDecodeDriverConfigRefusesLossyNumbers(t *testing.T) {
	yamlValue := func(text string) any {
		var v any
		require.NoError(t, yaml.Unmarshal([]byte(text), &v))
		return v
	}
	tests := []struct {
		value any
		name  string
		path  string
		want  string
	}{
		{name: "yaml fraction", path: "queue_size", value: yamlValue("1.9"), want: "runtime.queue_size: must be an integer"},
		{name: "yaml beyond int64 as float", path: "workers", value: yamlValue("99999999999999999999"), want: "runtime.workers: is out of range"},
		{name: "yaml two to the 63 as uint64", path: "workers", value: yamlValue("9223372036854775808"), want: "runtime.workers: is out of range"},
		{name: "yaml infinity", path: "workers", value: yamlValue(".inf"), want: "runtime.workers: is out of range"},
		{name: "yaml NaN", path: "workers", value: yamlValue(".nan"), want: "runtime.workers: must be an integer"},
		{name: "yaml bool", path: "workers", value: yamlValue("true"), want: "runtime.workers: must be an integer"},
		{name: "api fraction", path: "queue_size", value: json.Number("1.9"), want: "runtime.queue_size: must be an integer"},
		{name: "api beyond int64", path: "queue_size", value: json.Number("99999999999999999999"), want: "runtime.queue_size: is out of range"},
		{name: "api exponent", path: "workers", value: json.Number("1e20"), want: "runtime.workers: is out of range"},
		{name: "float beyond int64", path: "workers", value: 1e20, want: "runtime.workers: is out of range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg runtimeTarget
			err := DecodeDriverConfig(map[string]any{"runtime": map[string]any{tt.path: tt.value}}, &cfg)
			require.EqualError(t, err, tt.want)
		})
	}

	t.Run("multiplier", func(t *testing.T) {
		for value, want := range map[any]string{
			yamlValue(".inf"):    "runtime.retry.multiplier: must be a finite number",
			yamlValue("-.inf"):   "runtime.retry.multiplier: must be a finite number",
			yamlValue("true"):    "runtime.retry.multiplier: must be a number",
			json.Number("1e400"): "runtime.retry.multiplier: is out of range",
		} {
			var cfg runtimeTarget
			err := DecodeDriverConfig(map[string]any{"runtime": map[string]any{"retry": map[string]any{"multiplier": value}}}, &cfg)
			require.EqualError(t, err, want, "%v", value)
		}
	})

	t.Run("exact values are kept", func(t *testing.T) {
		var cfg runtimeTarget
		err := DecodeDriverConfig(map[string]any{"runtime": map[string]any{
			"workers": json.Number("4"), "queue_size": 2.0, "retry": map[string]any{"multiplier": json.Number("1.5"), "max_attempts": uint64(3)},
		}}, &cfg)
		require.NoError(t, err)
		assert.Equal(t, 4, cfg.Runtime.Workers)
		assert.Equal(t, 2, cfg.Runtime.QueueSize)
		assert.InDelta(t, 1.5, cfg.Runtime.Retry.Multiplier, 0)
		assert.Equal(t, 3, cfg.Runtime.Retry.MaxAttempts)
		assert.NotEqual(t, math.MaxInt, cfg.Runtime.Workers)
	})
}

func TestDecodeDriverConfigRefusesValuesOfAnotherType(t *testing.T) {
	type target struct {
		Labels  map[string]string    `mapstructure:"labels"`
		Name    string               `mapstructure:"name"`
		Tags    []string             `mapstructure:"tags"`
		Runtime output.RuntimeConfig `mapstructure:"runtime"`
		On      bool                 `mapstructure:"on"`
	}
	yamlValue := func(text string) any {
		var v any
		require.NoError(t, yaml.Unmarshal([]byte(text), &v))
		return v
	}
	runtime := func(key string, value any) map[string]any {
		return map[string]any{"runtime": map[string]any{key: value}}
	}
	tests := []struct {
		raw   map[string]any
		check func(t *testing.T, got target)
		name  string
		want  string
	}{
		{name: "yaml two", raw: map[string]any{"on": yamlValue("2")}, want: "on: must be true or false"},
		{name: "yaml one", raw: map[string]any{"on": yamlValue("1")}, want: "on: must be true or false"},
		{name: "yaml zero", raw: map[string]any{"on": yamlValue("0")}, want: "on: must be true or false"},
		{name: "yaml float", raw: map[string]any{"on": yamlValue("1.0")}, want: "on: must be true or false"},
		{name: "yaml word", raw: map[string]any{"on": yamlValue("yes")}, want: "on: must be true or false"},
		{name: "yaml map", raw: map[string]any{"on": yamlValue("{a: 1}")}, want: "on: must be true or false"},
		{name: "yaml runtime health_check two", raw: runtime("health_check", yamlValue("2")), want: "runtime.health_check: must be true or false"},
		{name: "yaml batching enabled two", raw: runtime("batching", map[string]any{"enabled": yamlValue("2")}), want: "runtime.batching.enabled: must be true or false"},
		{name: "api two", raw: map[string]any{"on": json.Number("2")}, want: "on: must be true or false"},
		{name: "api one", raw: map[string]any{"on": json.Number("1")}, want: "on: must be true or false"},
		{name: "api zero", raw: map[string]any{"on": json.Number("0")}, want: "on: must be true or false"},
		{name: "api runtime health_check two", raw: runtime("health_check", json.Number("2")), want: "runtime.health_check: must be true or false"},
		{name: "yaml boolean", raw: map[string]any{"on": yamlValue("true")}, check: func(t *testing.T, got target) { assert.True(t, got.On) }},
		{name: "yaml quoted boolean", raw: map[string]any{"on": yamlValue(`"false"`)}, check: func(t *testing.T, got target) { assert.False(t, got.On) }},
		{name: "api boolean", raw: map[string]any{"on": true}, check: func(t *testing.T, got target) { assert.True(t, got.On) }},
		{name: "yaml number for a duration", raw: runtime("retry", map[string]any{"initial_interval": yamlValue("30")}),
			want: "runtime.retry.initial_interval: must be a duration such as 30s or 1m"},
		{name: "api number for a duration", raw: runtime("retry", map[string]any{"initial_interval": json.Number("30")}),
			want: "runtime.retry.initial_interval: must be a duration such as 30s or 1m"},
		{name: "yaml zero duration", raw: runtime("retry", map[string]any{"initial_interval": yamlValue("0")}),
			check: func(t *testing.T, got target) { assert.Zero(t, got.Runtime.Retry.InitialInterval) }},
		{name: "yaml single value for a list", raw: map[string]any{"tags": yamlValue("a")}, want: "tags: must be a list"},
		{name: "api single value for a list", raw: map[string]any{"tags": json.Number("1")}, want: "tags: must be a list"},
		{name: "yaml number for a string", raw: map[string]any{"name": yamlValue("7")}, check: func(t *testing.T, got target) { assert.Equal(t, "7", got.Name) }},
		{name: "yaml boolean for a string", raw: map[string]any{"name": yamlValue("true")}, check: func(t *testing.T, got target) { assert.Equal(t, "true", got.Name) }},
		{name: "api number for a string", raw: map[string]any{"name": json.Number("7")}, check: func(t *testing.T, got target) { assert.Equal(t, "7", got.Name) }},
		{name: "yaml list for a string", raw: map[string]any{"name": yamlValue("[a]")}, want: "name: invalid type, expected string"},
		{name: "yaml list for a map", raw: map[string]any{"labels": yamlValue("[{a: b}]")}, want: "labels: invalid type, expected map"},
		{name: "yaml map values are text", raw: map[string]any{"labels": yamlValue("{tier: 1, debug: true}")},
			check: func(t *testing.T, got target) {
				assert.Equal(t, map[string]string{"tier": "1", "debug": "true"}, got.Labels)
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got target
			err := DecodeDriverConfig(tt.raw, &got)
			if tt.want != "" {
				require.EqualError(t, err, tt.want)
				return
			}
			require.NoError(t, err)
			tt.check(t, got)
		})
	}
}

func TestDecodeDriverConfigDropsNulls(t *testing.T) {
	raw := map[string]any{"name": nil, "runtime": map[string]any{"workers": nil, "retry": nil}}
	var cfg runtimeTarget
	require.NoError(t, DecodeDriverConfig(raw, &cfg))
	assert.Equal(t, map[string]any{"runtime": map[string]any{}}, raw, "a presence check on raw sees no key")
	assert.Zero(t, cfg.Runtime.Workers)
	assert.Nil(t, cfg.Runtime.Retry)

	for _, raw := range []map[string]any{
		{"typo": nil},
		{"Name": "x", "runtime": map[string]any{"wrokers": nil}},
	} {
		err := DecodeDriverConfig(raw, &cfg)
		require.Error(t, err, "null means omitted for a known key only")
		assert.Contains(t, err.Error(), "unknown keys: ")
	}
}

func TestWithDefaultOverridesOneFieldOnACopy(t *testing.T) {
	base := BatchRuntimeConfigSchemaFields()
	got := WithDefault(base, "runtime.batching.enabled", true)
	for i := range got {
		if got[i].Name == "runtime.batching.enabled" {
			assert.Equal(t, true, got[i].Default)
			assert.True(t, got[i].OutputDefault, "the override is marked as the output's own")
			assert.Equal(t, false, base[i].Default, "the shared fields are not changed")
			assert.False(t, base[i].OutputDefault)
		} else {
			assert.Equal(t, base[i], got[i])
		}
	}
	assert.Panics(t, func() { WithDefault(base, "runtime.nope", 1) })
}
