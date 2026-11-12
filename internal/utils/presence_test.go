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

package utils

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDropNulls(t *testing.T) {
	cfg := map[string]any{
		"gone": nil, "kept": "x", "zero": 0, "off": false, "empty": "",
		"nested": map[string]any{"gone": nil, "deeper": map[string]any{"gone": nil, "n": 1}},
		"list":   []any{nil, map[string]any{"gone": nil, "v": 2}},
	}
	DropNulls(cfg)
	assert.Equal(t, map[string]any{
		"kept": "x", "zero": 0, "off": false, "empty": "",
		"nested": map[string]any{"deeper": map[string]any{"n": 1}},
		"list":   []any{nil, map[string]any{"v": 2}},
	}, cfg, "only nulls go; zero, false and empty are values; list elements stay")
	DropNulls(nil)
}

func TestMergePatch(t *testing.T) {
	tests := []struct {
		dst, patch, want map[string]any
		name             string
	}{
		{name: "absent keys are kept", dst: map[string]any{"a": 1, "b": 2}, patch: map[string]any{"b": 3},
			want: map[string]any{"a": 1, "b": 3}},
		{name: "null removes", dst: map[string]any{"a": 1, "b": 2}, patch: map[string]any{"b": nil}, want: map[string]any{"a": 1}},
		{name: "null on an absent key", dst: map[string]any{"a": 1}, patch: map[string]any{"z": nil}, want: map[string]any{"a": 1}},
		{name: "objects merge", dst: map[string]any{"o": map[string]any{"x": 1, "y": 2}}, patch: map[string]any{"o": map[string]any{"y": nil, "z": 3}},
			want: map[string]any{"o": map[string]any{"x": 1, "z": 3}}},
		{name: "object replaces a scalar, without its nulls", dst: map[string]any{"o": "s"}, patch: map[string]any{"o": map[string]any{"n": nil, "v": 1}},
			want: map[string]any{"o": map[string]any{"v": 1}}},
		{name: "scalar replaces an object", dst: map[string]any{"o": map[string]any{"x": 1}}, patch: map[string]any{"o": 5}, want: map[string]any{"o": 5}},
		{name: "lists replace, nulls inside objects dropped", dst: map[string]any{"l": []any{1, 2}}, patch: map[string]any{"l": []any{map[string]any{"n": nil}}},
			want: map[string]any{"l": []any{map[string]any{}}}},
		{name: "false and zero are values", dst: map[string]any{"b": true, "n": 3}, patch: map[string]any{"b": false, "n": 0},
			want: map[string]any{"b": false, "n": 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			MergePatch(tt.dst, tt.patch)
			assert.Equal(t, tt.want, tt.dst)
		})
	}
}

func TestMergePatchDoesNotRetainThePatch(t *testing.T) {
	inner := []any{"a"}
	patch := map[string]any{"l": inner, "o": map[string]any{"k": "v"}}
	dst := map[string]any{}
	MergePatch(dst, patch)
	const mutated = "mutated"
	inner[0] = mutated
	patch["o"].(map[string]any)["k"] = mutated
	assert.Equal(t, map[string]any{"l": []any{"a"}, "o": map[string]any{"k": "v"}}, dst)
}

func TestIsSet(t *testing.T) {
	for _, tt := range []struct {
		value any
		want  bool
	}{{nil, false}, {"", false}, {"x", true}, {0, true}, {false, true}, {[]any{}, true}} {
		assert.Equal(t, tt.want, IsSet(tt.value), "%#v", tt.value)
	}
}

func TestRanges(t *testing.T) {
	ints := IntRange{Min: 1, Max: 256}
	for _, tt := range []struct {
		v    int
		want bool
	}{{0, false}, {1, true}, {256, true}, {257, false}} {
		var errs ValidationErrors
		ints.Check(&errs, "workers", tt.v)
		assert.Equal(t, tt.want, len(errs) == 0, "%d", tt.v)
	}
	assert.Equal(t, "must be an integer between 1 and 256", ints.Message())

	floats := FloatRange{Min: 1, Max: 10}
	for _, tt := range []struct {
		v    float64
		want bool
	}{{0.999, false}, {1, true}, {10, true}, {10.001, false}, {math.NaN(), false}, {math.Inf(1), false}} {
		assert.Equal(t, tt.want, floats.Contains(tt.v), "%v", tt.v)
	}
	var errs ValidationErrors
	floats.Check(&errs, "multiplier", 0.5)
	assert.Equal(t, "multiplier: must be a number between 1 and 10", errs.Error())

	durations := DurationRange{Min: time.Millisecond, Max: time.Hour}
	for _, tt := range []struct {
		v    time.Duration
		want bool
	}{{time.Millisecond - 1, false}, {time.Millisecond, true}, {time.Hour, true}, {time.Hour + 1, false}} {
		assert.Equal(t, tt.want, durations.Contains(tt.v), "%v", tt.v)
	}
	errs = nil
	durations.Check(&errs, "interval", 0)
	assert.Equal(t, "interval: must be a duration between 1ms and 1h", errs.Error())
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "0s", time.Millisecond: "1ms", 1500 * time.Millisecond: "1.5s", 30 * time.Second: "30s",
		90 * time.Second: "90s", 5 * time.Minute: "5m", time.Hour: "1h", 36 * time.Hour: "36h", -time.Second: "-1s",
	} {
		assert.Equal(t, want, FormatDuration(d))
		parsed, err := time.ParseDuration(want)
		assert.NoError(t, err)
		assert.Equal(t, d, parsed, "the text reads back as the same duration")
	}
}
