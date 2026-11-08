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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeHeaderLists(t *testing.T) {
	for _, tt := range []struct {
		raw  any
		name string
		want ValueSources
	}{
		{map[string]any{"values": []string{"public"}, "secrets": []any{"protected"}, "files": []string{"key"}}, "lists", ValueSources{
			Values: []string{"public"}, Secrets: []string{"protected"}, Files: []string{"key"},
		}},
		{map[string]any{"VaLuEs": []any{"public"}, "SECRETS": []string{"protected"}, "FILES": []any{"key"}}, "case aliases", ValueSources{
			Values: []string{"public"}, Secrets: []string{"protected"}, Files: []string{"key"},
		}},
		{map[string][]string{"values": {"public"}}, "typed map", ValueSources{Values: []string{"public"}}},
		{map[any]any{"values": []string{"public"}}, "interface map", ValueSources{Values: []string{"public"}}},
		{map[string]any{"values": nil, "secrets": nil, "files": nil}, "null lists", ValueSources{}},
		{map[string]any{}, "empty entry", ValueSources{}},
		{nil, "null entry", ValueSources{}},
		{ValueSources{Secrets: []string{"protected"}}, "typed entry", ValueSources{Secrets: []string{"protected"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var cfg HTTPConfig
			require.NoError(t, DecodeDriverConfig(map[string]any{"headers": map[string]any{"X-Key": tt.raw}}, &cfg))
			assert.Equal(t, tt.want, cfg.Headers["X-Key"])
		})
	}
	t.Run("empty lists", func(t *testing.T) {
		var cfg HTTPConfig
		require.NoError(t, DecodeDriverConfig(map[string]any{"headers": map[string]any{
			"X-Key": map[string]any{"values": []string{}, "secrets": []any{}, "files": []string{}},
		}}, &cfg))
		assert.Empty(t, cfg.Headers["X-Key"].Values)
		assert.Empty(t, cfg.Headers["X-Key"].Secrets)
		assert.Empty(t, cfg.Headers["X-Key"].Files)
	})
}

func TestDecodeHeaderRejectsMalformedFields(t *testing.T) {
	const credential = "private-credential-canary"
	for _, field := range []string{"values", "secrets", "files"} {
		for _, tt := range []struct {
			raw  any
			name string
		}{
			{credential, "scalar string"},
			{42, "number"},
			{true, "boolean"},
			{[]byte(credential), "bytes"},
			{[]any{credential, 42}, "number element"},
			{[]any{credential, nil}, "null element"},
			{[]any{credential, true}, "boolean element"},
			{map[string]any{"nested": credential}, "map"},
			{[]any{map[string]any{"nested": credential}}, "map element"},
			{[]any{[]string{credential}}, "list element"},
		} {
			t.Run(field+"/"+tt.name, func(t *testing.T) {
				var cfg HTTPConfig
				err := DecodeDriverConfig(map[string]any{"headers": map[string]any{
					"X-Key": map[string]any{field: tt.raw},
				}}, &cfg)
				require.Error(t, err)
				assert.Contains(t, err.Error(), field)
				assert.NotContains(t, err.Error(), credential)
			})
		}
	}
}

func TestDecodeHeaderRejectsAmbiguousOrUnknownProperties(t *testing.T) {
	const credential = "private-credential-canary"
	for _, tt := range []struct {
		raw  any
		name string
	}{
		{map[string]any{"values": []string{credential}, "VALUES": nil}, "values aliases"},
		{map[string]any{"Secrets": []string{credential}, "sEcReTs": []string{"other"}}, "noncanonical aliases"},
		{map[string]any{"secrets": []string{credential}, "\u017fecrets": nil}, "unicode EqualFold alias"},
		{map[string]any{"files": []string{credential}, "Files": nil}, "files aliases"},
		{map[string]any{credential: []string{credential}}, "unknown property"},
		{map[string]any{"secrets_file": credential}, "unsupported file alias"},
		{map[any]any{17: credential}, "nonstring key"},
		{credential, "scalar entry"},
		{[]any{credential}, "list entry"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for range 20 {
				var cfg HTTPConfig
				err := DecodeDriverConfig(map[string]any{"headers": map[string]any{"X-Key": tt.raw}}, &cfg)
				require.Error(t, err)
				assert.NotContains(t, err.Error(), credential)
			}
		})
	}
}

func TestDecodeHeaderHookPreservesOtherDecodes(t *testing.T) {
	var cfg struct {
		Labels   map[string]string `mapstructure:"labels"`
		Name     string            `mapstructure:"name"`
		Delay    time.Duration     `mapstructure:"delay"`
		Attempts int               `mapstructure:"attempts"`
	}
	require.NoError(t, DecodeDriverConfig(map[string]any{
		"name": 123, "attempts": "3", "delay": "2s", "labels": map[string]any{"secrets": 456},
	}, &cfg))
	assert.Equal(t, "123", cfg.Name)
	assert.Equal(t, 3, cfg.Attempts)
	assert.Equal(t, 2*time.Second, cfg.Delay)
	assert.Equal(t, map[string]string{"secrets": "456"}, cfg.Labels)
	assert.Error(t, DecodeDriverConfig(map[string]any{"unknown": true}, &cfg))
}
