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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeDecodeErrorFailsClosed(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	assert.Equal(t, "invalid value", safeDecodeReason(errors.New("future library text with "+sentinel)))
	assert.Equal(t, "invalid value", SafeDecodeError(errors.New("plain "+sentinel), nil).Error())
	joined := fmt.Errorf("wrapped: %w", errors.Join(errors.New("a "+sentinel), errors.New("b "+sentinel)))
	assert.Equal(t, "invalid value; invalid value", SafeDecodeError(joined, nil).Error())
}

func TestValidationErrorWithoutField(t *testing.T) {
	assert.Equal(t, "at least one of logs or metrics is required",
		ValidationErrors{{Message: "at least one of logs or metrics is required"}}.Error())
	assert.Equal(t, "a: x; y", ValidationErrors{{Field: "a", Message: "x"}, {Message: "y"}}.Error())
}

func TestSafeDecodeErrorFieldsAndReasons(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	var target struct {
		Nested struct {
			Wait time.Duration `mapstructure:"wait"`
		} `mapstructure:"nested"`
		Ratio float64 `mapstructure:"ratio"`
		Count int     `mapstructure:"count"`
		On    bool    `mapstructure:"on"`
	}
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: TypeHooks(),
		Result:     &target,
	})
	require.NoError(t, err)
	err = dec.Decode(map[string]any{
		"nested": map[string]any{"wait": sentinel}, "ratio": sentinel, "count": sentinel, "on": sentinel,
	})
	require.Error(t, err)
	errs := SafeDecodeError(err, reflect.TypeOf(&target))
	assert.Equal(t, ValidationErrors{
		{Field: "count", Message: "must be an integer"},
		{Field: "nested.wait", Message: "must be a duration such as 30s or 1m"},
		{Field: "on", Message: "must be true or false"},
		{Field: "ratio", Message: "must be a number"},
	}, errs)
	assert.NotContains(t, errs.Error(), sentinel)

	require.NoError(t, dec.Decode(map[string]any{"nested": map[string]any{"wait": "1m30s"}}))
	assert.Equal(t, 90*time.Second, target.Nested.Wait)
}

// No production hook produces a ParseError; the branch must still not quote the value.
func TestSafeDecodeReasonParseErrorKinds(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	for kind, want := range map[any]string{false: "must be true or false", 0: "must be an integer", 0.5: "must be a number"} {
		err := &mapstructure.ParseError{Expected: reflect.ValueOf(kind), Value: sentinel, Err: errors.New("parsing " + sentinel)}
		assert.Equal(t, want, safeDecodeReason(err))
	}
}

type typedTarget struct {
	Name   string            `mapstructure:"name"`
	Labels map[string]string `mapstructure:"labels"`
	Maybe  *bool             `mapstructure:"maybe"`
	Tags   []string          `mapstructure:"tags"`
	Wait   time.Duration     `mapstructure:"wait"`
	Count  int               `mapstructure:"count"`
	On     bool              `mapstructure:"on"`
}

func decodeTyped(t *testing.T, raw map[string]any) (typedTarget, error) {
	t.Helper()
	var out typedTarget
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{ErrorUnused: true, DecodeHook: TypeHooks(), Result: &out})
	require.NoError(t, err)
	if err := dec.Decode(raw); err != nil {
		return out, SafeDecodeError(err, reflect.TypeOf(out))
	}
	return out, nil
}

func TestDurationValue(t *testing.T) {
	const refused = "must be a duration such as 30s or 1m"
	for _, tt := range []struct {
		value any
		name  string
		err   string
		want  time.Duration
	}{
		{name: "text", value: "1m30s", want: 90 * time.Second},
		{name: "zero text", value: "0s"},
		{name: "duration", value: time.Minute, want: time.Minute},
		{name: "integer zero", value: 0},
		{name: "int64 zero", value: int64(0)},
		{name: "uint zero", value: uint8(0)},
		{name: "json zero", value: json.Number("0")},
		{name: "integer", value: 30, err: refused},
		{name: "negative integer", value: -1, err: refused},
		{name: "json integer", value: json.Number("30"), err: refused},
		{name: "float zero", value: 0.0, err: refused},
		{name: "json float zero", value: json.Number("0.0"), err: refused},
		{name: "json exponent zero", value: json.Number("0e0"), err: refused},
		{name: "bool", value: false, err: refused},
		{name: "nil", value: nil, err: refused},
		{name: "text without unit", value: "30", err: refused},
		{name: "list", value: []any{"1s"}, err: refused},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DurationValue(tt.value)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTypeHooks(t *testing.T) {
	tests := []struct {
		value any
		check func(t *testing.T, got typedTarget)
		name  string
		key   string
		want  string // empty: accepted
	}{
		{name: "bool", key: "on", value: true, check: func(t *testing.T, got typedTarget) { assert.True(t, got.On) }},
		{name: "bool text", key: "on", value: "true", check: func(t *testing.T, got typedTarget) { assert.True(t, got.On) }},
		{name: "bool text false", key: "on", value: "False", check: func(t *testing.T, got typedTarget) { assert.False(t, got.On) }},
		{name: "bool text one", key: "on", value: "1", check: func(t *testing.T, got typedTarget) { assert.True(t, got.On) }},
		{name: "bool pointer", key: "maybe", value: false, check: func(t *testing.T, got typedTarget) { assert.Equal(t, new(false), got.Maybe) }},
		{name: "bool pointer from number", key: "maybe", value: 2, want: "maybe: must be true or false"},
		{name: "bool from two", key: "on", value: 2, want: "on: must be true or false"},
		{name: "bool from one", key: "on", value: 1, want: "on: must be true or false"},
		{name: "bool from zero", key: "on", value: 0, want: "on: must be true or false"},
		{name: "bool from uint", key: "on", value: uint64(1), want: "on: must be true or false"},
		{name: "bool from float", key: "on", value: 1.0, want: "on: must be true or false"},
		{name: "bool from json number", key: "on", value: json.Number("1"), want: "on: must be true or false"},
		{name: "bool from json two", key: "on", value: json.Number("2"), want: "on: must be true or false"},
		{name: "bool from word", key: "on", value: "yes", want: "on: must be true or false"},
		{name: "bool from empty text", key: "on", value: "", want: "on: must be true or false"},
		{name: "bool from map", key: "on", value: map[string]any{}, want: "on: must be true or false"},
		{name: "bool from list", key: "on", value: []any{true}, want: "on: must be true or false"},
		{name: "string", key: "name", value: "x", check: func(t *testing.T, got typedTarget) { assert.Equal(t, "x", got.Name) }},
		{name: "string from int", key: "name", value: 7, check: func(t *testing.T, got typedTarget) { assert.Equal(t, "7", got.Name) }},
		{name: "string from float", key: "name", value: 1.5, check: func(t *testing.T, got typedTarget) { assert.Equal(t, "1.5", got.Name) }},
		{name: "string from bool", key: "name", value: true, check: func(t *testing.T, got typedTarget) { assert.Equal(t, "true", got.Name) }},
		{name: "string from json number", key: "name", value: json.Number("0123"), check: func(t *testing.T, got typedTarget) { assert.Equal(t, "0123", got.Name) }},
		{name: "string from map", key: "name", value: map[string]any{}, want: "name: invalid type, expected string"},
		{name: "string from list", key: "name", value: []any{"a"}, want: "name: invalid type, expected string"},
		{name: "list", key: "tags", value: []any{"a", "b"}, check: func(t *testing.T, got typedTarget) { assert.Equal(t, []string{"a", "b"}, got.Tags) }},
		{name: "list from string", key: "tags", value: "a", want: "tags: must be a list"},
		{name: "list from number", key: "tags", value: 1, want: "tags: must be a list"},
		{name: "list from map", key: "tags", value: map[string]any{}, want: "tags: must be a list"},
		{name: "duration", key: "wait", value: "30s", check: func(t *testing.T, got typedTarget) { assert.Equal(t, 30*time.Second, got.Wait) }},
		{name: "duration value", key: "wait", value: time.Minute, check: func(t *testing.T, got typedTarget) { assert.Equal(t, time.Minute, got.Wait) }},
		{name: "duration from number", key: "wait", value: 30, want: "wait: must be a duration such as 30s or 1m"},
		{name: "duration zero needs no unit", key: "wait", value: 0, check: func(t *testing.T, got typedTarget) { assert.Zero(t, got.Wait) }},
		{name: "duration from uint zero", key: "wait", value: uint64(0), check: func(t *testing.T, got typedTarget) { assert.Zero(t, got.Wait) }},
		{name: "duration from json zero", key: "wait", value: json.Number("0"), check: func(t *testing.T, got typedTarget) { assert.Zero(t, got.Wait) }},
		{name: "duration from float zero", key: "wait", value: 0.0, want: "wait: must be a duration such as 30s or 1m"},
		{name: "duration from json float zero", key: "wait", value: json.Number("0.0"), want: "wait: must be a duration such as 30s or 1m"},
		{name: "duration from json number", key: "wait", value: json.Number("30"), want: "wait: must be a duration such as 30s or 1m"},
		{name: "duration from bool", key: "wait", value: true, want: "wait: must be a duration such as 30s or 1m"},
		{name: "int from bool", key: "count", value: true, want: "count: must be an integer"},
		{name: "map values are text", key: "labels", value: map[string]any{"tier": 1, "debug": true},
			check: func(t *testing.T, got typedTarget) {
				assert.Equal(t, map[string]string{"tier": "1", "debug": "true"}, got.Labels)
			}},
		{name: "map from list is not merged", key: "labels", value: []any{map[string]any{"a": "1"}}, want: "labels: invalid type, expected map"},
		{name: "map from empty list", key: "labels", value: []any{}, want: "labels: invalid type, expected map"},
		{name: "map from text", key: "labels", value: "a", want: "labels: invalid type, expected map"},
		{name: "int from text", key: "count", value: "4", check: func(t *testing.T, got typedTarget) { assert.Equal(t, 4, got.Count) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeTyped(t, map[string]any{tt.key: tt.value})
			if tt.want != "" {
				require.Error(t, err)
				assert.Equal(t, tt.want, err.Error())
				return
			}
			require.NoError(t, err)
			tt.check(t, got)
		})
	}
}
