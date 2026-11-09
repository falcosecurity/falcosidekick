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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
)

// The chart refuses the secrets of this file: a new secret field without make chart.secret-fields fails here.
func TestSecretFieldsAreUpToDate(t *testing.T) {
	current, err := os.ReadFile(filepath.Join("..", "..", Path))
	require.NoError(t, err, "run make chart.secret-fields")
	assert.Equal(t, Generate(all.Types()), string(current), "%s is out of date: run make chart.secret-fields", Path)
}

func TestGenerateListsStringSecretsAndEntrySecrets(t *testing.T) {
	types := []output.Type{
		{Name: "plain", Schema: output.Schema{Fields: []output.SchemaField{{Name: "host", Type: "string"}}}},
		{Name: "b", Schema: output.Schema{Fields: []output.SchemaField{
			{Name: "token", Type: "string", Secret: true},
			{Name: "auth.password", Type: "string", Secret: true},
			{Name: "headers", Type: "map", EntryFields: []output.SchemaField{
				{Name: "values", Type: "string[]"},
				{Name: "secrets", Type: "string[]", Secret: true},
			}},
		}}},
		{Name: "a", Schema: output.Schema{Fields: []output.SchemaField{{Name: "key", Type: "string", Secret: true}}}},
	}
	var got map[string]struct {
		Entries map[string][]string `yaml:"entries"`
		Fields  []string            `yaml:"fields"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(Generate(types)), &got))
	assert.Len(t, got, 2, "types without secrets are left out")
	assert.Equal(t, []string{"key"}, got["a"].Fields)
	assert.Equal(t, []string{"auth.password", "token"}, got["b"].Fields)
	assert.Equal(t, map[string][]string{"headers": {"secrets"}}, got["b"].Entries)
}
