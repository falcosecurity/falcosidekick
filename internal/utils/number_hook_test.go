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
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type numberTarget struct {
	Any      any           `mapstructure:"any"`
	Text     string        `mapstructure:"text"`
	Int      int           `mapstructure:"int"`
	Uint     uint          `mapstructure:"uint"`
	Float    float64       `mapstructure:"float"`
	Duration time.Duration `mapstructure:"duration"`
	Float32  float32       `mapstructure:"float32"`
	Int32    int32         `mapstructure:"int32"`
	Uint16   uint16        `mapstructure:"uint16"`
	Int8     int8          `mapstructure:"int8"`
}

func decodeNumbers(raw map[string]any) (numberTarget, error) {
	var out numberTarget
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		ErrorUnused: true,
		DecodeHook:  TypeHooks(),
		Result:      &out,
	})
	if err != nil {
		return out, err
	}
	if err := dec.Decode(raw); err != nil {
		return out, SafeDecodeError(err, reflect.TypeOf(out))
	}
	return out, nil
}

// A float above int64 converts to MaxInt64 on arm64 and MinInt64 on amd64; the hook refuses it on both.
func TestNumberHook(t *testing.T) {
	tests := []struct {
		value any
		check func(t *testing.T, got numberTarget)
		name  string
		key   string
		want  string // empty: accepted
	}{
		{name: "int", key: "int", value: 42, check: func(t *testing.T, got numberTarget) { assert.Equal(t, 42, got.Int) }},
		{name: "integral float", key: "int", value: 4.0, check: func(t *testing.T, got numberTarget) { assert.Equal(t, 4, got.Int) }},
		{name: "fraction", key: "int", value: 1.9, want: "int: must be an integer"},
		{name: "negative fraction", key: "int", value: -0.5, want: "int: must be an integer"},
		{name: "float saturating on arm64 and wrapping on amd64", key: "int", value: 1e20, want: "int: is out of range"},
		{name: "negative float beyond int64", key: "int", value: -1e20, want: "int: is out of range"},
		{name: "two to the 63 as float", key: "int", value: math.Exp2(63), want: "int: is out of range"},
		{name: "largest float below two to the 63", key: "int", value: math.Nextafter(math.Exp2(63), 0),
			check: func(t *testing.T, got numberTarget) { assert.Equal(t, int(math.Nextafter(math.Exp2(63), 0)), got.Int) }},
		{name: "minus two to the 63", key: "int", value: -math.Exp2(63), check: func(t *testing.T, got numberTarget) { assert.Equal(t, math.MinInt, got.Int) }},
		{name: "uint64 above int64 wraps negative without the hook", key: "int", value: uint64(1 << 63), want: "int: is out of range"},
		{name: "uint64 max int64", key: "int", value: uint64(math.MaxInt64), check: func(t *testing.T, got numberTarget) { assert.Equal(t, math.MaxInt, got.Int) }},
		{name: "positive infinity", key: "int", value: math.Inf(1), want: "int: is out of range"},
		{name: "negative infinity", key: "int", value: math.Inf(-1), want: "int: is out of range"},
		{name: "NaN", key: "int", value: math.NaN(), want: "int: must be an integer"},
		{name: "true", key: "int", value: true, want: "int: must be an integer"},
		{name: "false", key: "int", value: false, want: "int: must be an integer"},
		{name: "numeric string", key: "int", value: "12", check: func(t *testing.T, got numberTarget) { assert.Equal(t, 12, got.Int) }},
		{name: "hex string", key: "int", value: "0x10", check: func(t *testing.T, got numberTarget) { assert.Equal(t, 16, got.Int) }},
		{name: "fractional string", key: "int", value: "1.5", want: "int: must be an integer"},
		{name: "huge string", key: "int", value: "99999999999999999999", want: "int: is out of range"},
		{name: "empty string", key: "int", value: "", want: "int: must be an integer"},
		{name: "word", key: "int", value: "abc", want: "int: must be an integer"},
		{name: "json integer", key: "int", value: json.Number("7"), check: func(t *testing.T, got numberTarget) { assert.Equal(t, 7, got.Int) }},
		{name: "json exponent integer", key: "int", value: json.Number("1e3"), check: func(t *testing.T, got numberTarget) { assert.Equal(t, 1000, got.Int) }},
		{name: "json fraction", key: "int", value: json.Number("1.9"), want: "int: must be an integer"},
		{name: "json huge", key: "int", value: json.Number("99999999999999999999"), want: "int: is out of range"},
		{name: "json huge exponent", key: "int", value: json.Number("1e400"), want: "int: is out of range"},
		{name: "int8 overflow", key: "int8", value: 128, want: "int8: is out of range"},
		{name: "int8 max", key: "int8", value: 127, check: func(t *testing.T, got numberTarget) { assert.Equal(t, int8(127), got.Int8) }},
		{name: "int32 overflow", key: "int32", value: int64(1) << 40, want: "int32: is out of range"},
		{name: "uint negative", key: "uint", value: -1, want: "uint: is out of range"},
		{name: "uint from uint64", key: "uint", value: uint64(1 << 63), check: func(t *testing.T, got numberTarget) { assert.Equal(t, uint(1<<63), got.Uint) }},
		{name: "uint16 overflow", key: "uint16", value: uint64(70000), want: "uint16: is out of range"},
		{name: "uint fraction", key: "uint", value: 2.5, want: "uint: must be an integer"},
		{name: "float", key: "float", value: 1.5, check: func(t *testing.T, got numberTarget) { assert.InDelta(t, 1.5, got.Float, 0) }},
		{name: "float from int", key: "float", value: 3, check: func(t *testing.T, got numberTarget) { assert.InDelta(t, 3.0, got.Float, 0) }},
		{name: "float from json", key: "float", value: json.Number("2.25"), check: func(t *testing.T, got numberTarget) { assert.InDelta(t, 2.25, got.Float, 0) }},
		{name: "float infinity", key: "float", value: math.Inf(1), want: "float: must be a finite number"},
		{name: "float NaN", key: "float", value: math.NaN(), want: "float: must be a finite number"},
		{name: "float NaN string", key: "float", value: "NaN", want: "float: must be a finite number"},
		{name: "float inf string", key: "float", value: "+Inf", want: "float: must be a finite number"},
		{name: "float huge string", key: "float", value: "1e400", want: "float: is out of range"},
		{name: "float bool", key: "float", value: true, want: "float: must be a number"},
		{name: "float word", key: "float", value: "abc", want: "float: must be a number"},
		{name: "float32 overflow", key: "float32", value: 1e39, want: "float32: is out of range"},
		{name: "duration string", key: "duration", value: "30s", check: func(t *testing.T, got numberTarget) { assert.Equal(t, 30*time.Second, got.Duration) }},
		{name: "duration from int is not nanoseconds", key: "duration", value: 5, want: "duration: must be a duration such as 30s or 1m"},
		{name: "duration huge float", key: "duration", value: 1e20, want: "duration: must be a duration such as 30s or 1m"},
		{name: "interface keeps the value", key: "any", value: 1.9, check: func(t *testing.T, got numberTarget) { assert.InDelta(t, 1.9, got.Any, 0) }},
		{name: "string target untouched", key: "text", value: "1.9", check: func(t *testing.T, got numberTarget) { assert.Equal(t, "1.9", got.Text) }},
		{name: "list into int is a type error", key: "int", value: []any{1}, want: "int: invalid type, expected int"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeNumbers(map[string]any{tt.key: tt.value})
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

func TestIntegerValueRejectsNonNumbers(t *testing.T) {
	for _, value := range []any{nil, []any{1}, map[string]any{}} {
		_, err := IntegerValue(value)
		require.ErrorIs(t, err, ErrNotNumeric)
		_, err = FloatValue(value)
		require.ErrorIs(t, err, ErrNotNumeric)
	}
}
