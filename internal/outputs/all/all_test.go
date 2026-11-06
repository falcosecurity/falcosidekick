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
