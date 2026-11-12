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

package output

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

func presenceSchema() Schema {
	return Schema{Fields: []SchemaField{
		{Name: "storage_type", Type: "enum", Values: []string{"stream", "list"}, Default: "stream"},
		{Name: "label", Type: "string"},
		{Name: "required_name", Type: "string", Required: true},
		{Name: "enabled", Type: "bool", Default: true},
		SchemaField{Name: "runtime.workers", Type: "int", Default: 2}.WithIntRange(WorkersRange),
		SchemaField{Name: "runtime.retry.multiplier", Type: "float", Default: 2.0}.WithFloatRange(MultiplierRange),
		SchemaField{Name: "runtime.retry.initial_interval", Type: "string", Default: "1s"}.WithDurationRange(IntervalRange),
		SchemaField{Name: "ttl", Type: "string", Default: "0"}.WithDurationRange(utils.DurationRange{Max: time.Hour}),
	}}
}

func TestSchemaNormalizeConfig(t *testing.T) {
	tests := []struct {
		cfg  map[string]any
		want map[string]any // the config after normalization, when accepted
		name string
		err  string
	}{
		{name: "null is left for the decoder", cfg: map[string]any{"label": nil, "typo": nil, "runtime": map[string]any{"workers": nil}},
			want: map[string]any{"label": nil, "typo": nil, "runtime": map[string]any{"workers": nil}}},
		{name: "empty enum with a default is unset", cfg: map[string]any{"storage_type": ""}, want: map[string]any{}},
		{name: "empty duration with a default is unset", cfg: map[string]any{"runtime": map[string]any{"retry": map[string]any{"initial_interval": ""}}},
			want: map[string]any{"runtime": map[string]any{"retry": map[string]any{}}}},
		{name: "empty string without a default is a value", cfg: map[string]any{"label": ""}, want: map[string]any{"label": ""}},
		{name: "empty required string is left to the driver", cfg: map[string]any{"required_name": ""}, want: map[string]any{"required_name": ""}},
		{name: "false is a value", cfg: map[string]any{"enabled": false}, want: map[string]any{"enabled": false}},
		{name: "explicit zero is refused", cfg: map[string]any{"runtime": map[string]any{"workers": 0}},
			err: "runtime.workers: must be an integer between 1 and 256"},
		{name: "explicit zero duration is refused", cfg: map[string]any{"runtime": map[string]any{"retry": map[string]any{"initial_interval": "0s"}}},
			err: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "explicit integer zero duration is refused", cfg: map[string]any{"runtime": map[string]any{"retry": map[string]any{"initial_interval": 0}}},
			err: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "json integer zero duration is refused", cfg: map[string]any{"runtime": map[string]any{"retry": map[string]any{"initial_interval": json.Number("0")}}},
			err: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "integer zero duration is accepted where the range allows it", cfg: map[string]any{"ttl": 0}, want: map[string]any{"ttl": 0}},
		{name: "zero text duration is accepted where the range allows it", cfg: map[string]any{"ttl": "0s"}, want: map[string]any{"ttl": "0s"}},
		{name: "json integer zero duration is accepted where the range allows it", cfg: map[string]any{"ttl": json.Number("0")},
			want: map[string]any{"ttl": json.Number("0")}},
		{name: "a number for a duration is left to the decoder", cfg: map[string]any{"runtime": map[string]any{"retry": map[string]any{"initial_interval": 30}}},
			want: map[string]any{"runtime": map[string]any{"retry": map[string]any{"initial_interval": 30}}}},
		{name: "min", cfg: map[string]any{"runtime": map[string]any{"workers": 1}}, want: map[string]any{"runtime": map[string]any{"workers": 1}}},
		{name: "max", cfg: map[string]any{"runtime": map[string]any{"workers": json.Number("256")}},
			want: map[string]any{"runtime": map[string]any{"workers": json.Number("256")}}},
		{name: "above max", cfg: map[string]any{"runtime": map[string]any{"workers": 257}}, err: "runtime.workers: must be an integer between 1 and 256"},
		{name: "huge", cfg: map[string]any{"runtime": map[string]any{"workers": 1e20}}, err: "runtime.workers: is out of range"},
		{name: "fraction", cfg: map[string]any{"runtime": map[string]any{"workers": 1.5}}, err: "runtime.workers: must be an integer"},
		{name: "keys match regardless of case", cfg: map[string]any{"Runtime": map[string]any{"WORKERS": 0}},
			err: "runtime.workers: must be an integer between 1 and 256"},
		{name: "float below min", cfg: map[string]any{"runtime": map[string]any{"retry": map[string]any{"multiplier": 0.5}}},
			err: "runtime.retry.multiplier: must be a number between 1 and 10"},
		{name: "float max", cfg: map[string]any{"runtime": map[string]any{"retry": map[string]any{"multiplier": 10}}},
			want: map[string]any{"runtime": map[string]any{"retry": map[string]any{"multiplier": 10}}}},
		{name: "duration above max", cfg: map[string]any{"runtime": map[string]any{"retry": map[string]any{"initial_interval": "2h"}}},
			err: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "wrong types are left to the decoder", cfg: map[string]any{"runtime": map[string]any{"workers": []any{1},
			"retry": map[string]any{"initial_interval": "soon", "multiplier": map[string]any{}}}},
			want: map[string]any{"runtime": map[string]any{"workers": []any{1},
				"retry": map[string]any{"initial_interval": "soon", "multiplier": map[string]any{}}}}},
		{name: "a section that is not a map is left to the decoder", cfg: map[string]any{"runtime": "x"}, want: map[string]any{"runtime": "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := presenceSchema().NormalizeConfig(tt.cfg)
			if tt.err != "" {
				assert.Equal(t, tt.err, errs.Error())
				return
			}
			assert.Empty(t, errs)
			assert.Equal(t, tt.want, tt.cfg)
		})
	}
}

func TestSchemaFieldRangesAreExposed(t *testing.T) {
	data, err := json.Marshal(presenceSchema().Fields[4:])
	assert.NoError(t, err)
	assert.JSONEq(t, `[
		{"name":"runtime.workers","type":"int","label":"","default":2,"min":1,"max":256,"required":false},
		{"name":"runtime.retry.multiplier","type":"float","label":"","default":2,"min":1,"max":10,"required":false},
		{"name":"runtime.retry.initial_interval","type":"string","label":"","default":"1s","min":"1ms","max":"1h","required":false},
		{"name":"ttl","type":"string","label":"","default":"0","min":"0s","max":"1h","required":false}
	]`, string(data))
}
