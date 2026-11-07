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
