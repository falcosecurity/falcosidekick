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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeepCopyMapShallowFields(t *testing.T) {
	src := map[string]any{"url": "http://example.com", "port": 9200}
	cp := DeepCopyMap(src)

	assert.Equal(t, src, cp)

	cp["url"] = "http://changed.com"
	assert.Equal(t, "http://example.com", src["url"])
}

func TestDeepCopyMapNestedMap(t *testing.T) {
	src := map[string]any{
		"tls": map[string]any{"ca_file": "/old/ca.crt", "enabled": true},
	}
	cp := DeepCopyMap(src)

	nested := cp["tls"].(map[string]any)
	nested["ca_file"] = "/new/ca.crt"

	origNested := src["tls"].(map[string]any)
	assert.Equal(t, "/old/ca.crt", origNested["ca_file"], "deep copy must isolate nested maps")
}

func TestDeepCopyMapIsolatesEveryContainer(t *testing.T) {
	src := map[string]any{
		"brokers": []any{"a:9092", map[string]any{"host": "b"}},
		"topics":  []string{"falco"},
		"labels":  map[string]string{"team": "sec"},
		"empty":   nil,
		"nilList": []string(nil),
	}
	cp := DeepCopyMap(src)
	assert.Equal(t, src, cp)

	const changed = "changed"
	cp["brokers"].([]any)[0] = changed
	cp["brokers"].([]any)[1].(map[string]any)["host"] = changed
	cp["topics"].([]string)[0] = changed
	cp["labels"].(map[string]string)["team"] = changed

	assert.Equal(t, "a:9092", src["brokers"].([]any)[0])
	assert.Equal(t, "b", src["brokers"].([]any)[1].(map[string]any)["host"])
	assert.Equal(t, "falco", src["topics"].([]string)[0])
	assert.Equal(t, "sec", src["labels"].(map[string]string)["team"])
	assert.Nil(t, cp["empty"])
	assert.Nil(t, cp["nilList"])
}

func TestDeepCopyMapKeepsNilContainers(t *testing.T) {
	src := map[string]any{"m": map[string]string(nil), "ids": map[int]any{1: nil}}
	cp := DeepCopyMap(src)
	assert.Nil(t, cp["m"])
	assert.Equal(t, map[int]any{1: nil}, cp["ids"])
}

func TestNavigateMap(t *testing.T) {
	cfg := map[string]any{"auth": map[string]any{"password": "x"}, "token": "y"}
	tests := []struct {
		name       string
		path       string
		wantParent map[string]any
		wantLeaf   string
	}{
		{name: "top level", path: "token", wantParent: cfg, wantLeaf: "token"},
		{name: "nested", path: "auth.password", wantParent: cfg["auth"].(map[string]any), wantLeaf: "password"},
		{name: "missing segment", path: "tls.ca_file"},
		{name: "scalar segment", path: "token.value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent, leaf := NavigateMap(cfg, tt.path)
			assert.Equal(t, tt.wantParent, parent)
			assert.Equal(t, tt.wantLeaf, leaf)
		})
	}
}

func TestDeepCopyMapNil(t *testing.T) {
	assert.Nil(t, DeepCopyMap(nil))
}

func TestDeepCopyMapEmpty(t *testing.T) {
	cp := DeepCopyMap(map[string]any{})
	assert.NotNil(t, cp)
	assert.Empty(t, cp)
}

func TestDeepMergeMap(t *testing.T) {
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
			dst:  map[string]any{"n": map[string]any{"a": 1, "b": 2}},
			src:  map[string]any{"n": map[string]any{"b": 3, "c": 4}},
			want: map[string]any{"n": map[string]any{"a": 1, "b": 3, "c": 4}},
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
		{
			name: "empty src leaves dst unchanged",
			dst:  map[string]any{"a": 1},
			src:  map[string]any{},
			want: map[string]any{"a": 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DeepMergeMap(tt.dst, tt.src)
			assert.Equal(t, tt.want, tt.dst)
		})
	}
}
