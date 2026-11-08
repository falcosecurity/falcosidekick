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

package all

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// The UI groups drivers by category: every registered driver picks one of output.Categories.
func TestEveryOutputHasAKnownCategory(t *testing.T) {
	used := make(map[output.Category]bool)
	for _, typ := range Types() {
		assert.True(t, typ.Category.Known(), "%s: category %q is not one of output.Categories", typ.Name, typ.Category)
		used[typ.Category] = true
	}
	for _, category := range output.Categories {
		assert.True(t, used[category], "category %q has no driver", category)
	}
}

// The UI and the generated docs show each field's description: every field says what it does.
func TestEveryFieldHasADescription(t *testing.T) {
	var visit func(outputName string, fields []output.SchemaField)
	visit = func(outputName string, fields []output.SchemaField) {
		for _, field := range fields {
			d := field.Description
			if assert.NotEmpty(t, d, "%s: %s", outputName, field.Name) {
				assert.True(t, strings.HasSuffix(d, "."), "%s: %s: a description is a sentence", outputName, field.Name)
				assert.NotEqual(t, strings.ToLower(field.Label)+".", strings.ToLower(d), "%s: %s: says more than the label", outputName, field.Name)
				assert.LessOrEqual(t, len(d), 320, "%s: %s: one or two sentences", outputName, field.Name)
			}
			visit(outputName, field.EntryFields)
		}
	}
	for _, typ := range Types() {
		visit(typ.Name, typ.Schema.Fields)
	}
}

// The API checks file paths against api.secret_dirs only for fields marked File, so a path field
// without the mark would let a request read any file.
func TestFilePathFieldsAreMarked(t *testing.T) {
	var visit func(outputName string, fields []output.SchemaField)
	visit = func(outputName string, fields []output.SchemaField) {
		for _, field := range fields {
			leaf := field.Name[strings.LastIndex(field.Name, ".")+1:]
			path := strings.HasSuffix(leaf, "_file") || leaf == "files" || leaf == "kubeconfig"
			assert.Equal(t, path, field.File, "%s: %s", outputName, field.Name)
			if field.File {
				assert.False(t, field.Secret, "%s: %s: a file field holds a path, not the secret", outputName, field.Name)
			}
			visit(outputName, field.EntryFields)
		}
	}
	for _, typ := range Types() {
		visit(typ.Name, typ.Schema.Fields)
	}
}
