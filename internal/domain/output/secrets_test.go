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
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVisitSecrets(t *testing.T) {
	fields := []SchemaField{
		{Name: "password", Type: "string", Secret: true},
		{Name: "auth.token", Type: "string", Secret: true},
		{Name: "host", Type: "string"},
		{Name: "headers", Type: "map", EntryFields: []SchemaField{
			{Name: "values", Type: "string[]"},
			{Name: "secrets", Type: "string[]", Secret: true},
		}},
	}
	cfg := map[string]any{
		"PASSWORD": "p",
		"auth":     map[string]any{"Token": "t", "user": "u"},
		"host":     "https://h",
		"headers": map[string]any{
			"X-Key":   map[string]any{"values": []any{"v"}, "secrets": []any{"s"}},
			"X-Plain": "not an object",
		},
		"tls": map[string]any{"ca_file": "/ca.pem"},
	}
	var visited []string
	VisitSecrets(cfg, fields, func(_ map[string]any, _ string, path []string) {
		visited = append(visited, strings.Join(path, "."))
	})
	slices.Sort(visited)
	assert.Equal(t, []string{"PASSWORD", "auth.Token", "headers.X-Key.secrets", "headers.X-Plain"}, visited,
		"names match case-insensitively; a header that is not an object is treated as secret")
}

func TestInlineSecrets(t *testing.T) {
	fields := []SchemaField{
		{Name: "password", Type: "string", Secret: true},
		{Name: "auth.token", Type: "string", Secret: true},
		{Name: "headers", Type: "map", EntryFields: []SchemaField{
			{Name: "values", Type: "string[]"},
			{Name: "secrets", Type: "string[]", Secret: true},
			{Name: "files", Type: "string[]"},
		}},
	}
	tests := []struct {
		cfg  map[string]any
		name string
		want []string
	}{
		{name: "references only", cfg: map[string]any{
			"password_file": "/run/secrets/p",
			"headers":       map[string]any{"X-Key": map[string]any{"files": []any{"/run/secrets/k"}}},
		}},
		{name: "empty values are not secrets", cfg: map[string]any{"password": "", "headers": map[string]any{"X": map[string]any{"secrets": []any{}}}}},
		{name: "inline", cfg: map[string]any{
			"Password": "p",
			"auth":     map[string]any{"token": "t"},
			"headers":  map[string]any{"X-Key": map[string]any{"secrets": []any{"s"}}},
		}, want: []string{
			"Password: secrets cannot be stored; use Password_file",
			"auth.token: secrets cannot be stored; use token_file",
			"headers.X-Key.secrets: secrets cannot be stored; use files",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, s := range InlineSecrets(tt.cfg, fields) {
				got = append(got, s.String())
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
