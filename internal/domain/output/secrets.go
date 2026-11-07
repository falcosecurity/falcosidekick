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
	"reflect"
	"slices"
	"strings"
)

// SecretVisitor receives the map that holds a secret value, its key, and the key path from the config root.
type SecretVisitor func(parent map[string]any, key string, path []string)

// VisitSecrets calls visit for every secret value of cfg that fields describe, keys matched
// case-insensitively. A secret-bearing container that is not an object is visited whole,
// so a malformed value never escapes as a public leaf.
func VisitSecrets(cfg map[string]any, fields []SchemaField, visit SecretVisitor) {
	visitSchemaSecrets(cfg, fields, nil, visit)
}

func visitSchemaSecrets(cfg map[string]any, fields []SchemaField, path []string, visit SecretVisitor) {
	for i := range fields {
		field := &fields[i]
		if field.Secret || len(field.EntryFields) > 0 {
			visitSecretPath(cfg, strings.Split(field.Name, "."), field, path, visit)
		}
	}
}

func visitSecretPath(cfg map[string]any, parts []string, field *SchemaField, path []string, visit SecretVisitor) {
	for key, value := range cfg {
		if !strings.EqualFold(key, parts[0]) {
			continue
		}
		next := append(slices.Clone(path), key)
		if len(parts) == 1 && field.Secret {
			visit(cfg, key, next)
			continue
		}
		child, ok := value.(map[string]any)
		if !ok {
			visit(cfg, key, next)
			continue
		}
		if len(parts) > 1 {
			visitSecretPath(child, parts[1:], field, next, visit)
			continue
		}
		for entryKey, entryValue := range child {
			entryPath := append(slices.Clone(next), entryKey)
			if entry, ok := entryValue.(map[string]any); ok {
				visitSchemaSecrets(entry, field.EntryFields, entryPath, visit)
			} else {
				visit(child, entryKey, entryPath)
			}
		}
	}
}

// InlineSecret is a secret value written in a config instead of read from a file.
type InlineSecret struct {
	// Path is the key path as written, dot separated.
	Path string
	// Use is the key that reads the value from a file instead.
	Use string
}

// String reports the secret without its value.
func (s InlineSecret) String() string {
	return s.Path + ": secrets cannot be stored; use " + s.Use
}

// InlineSecrets returns the secrets cfg sets inline, sorted by path.
func InlineSecrets(cfg map[string]any, fields []SchemaField) []InlineSecret {
	var found []InlineSecret
	VisitSecrets(cfg, fields, func(parent map[string]any, key string, path []string) {
		if !hasValue(parent[key]) {
			return
		}
		use := "files"
		joined := strings.Join(path, ".")
		for i := range fields {
			if strings.EqualFold(fields[i].Name, joined) && fields[i].HasFileVariant() {
				use = key + "_file"
			}
		}
		found = append(found, InlineSecret{Path: joined, Use: use})
	})
	slices.SortFunc(found, func(a, b InlineSecret) int { return strings.Compare(a.Path, b.Path) })
	return found
}

func hasValue(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String, reflect.Map, reflect.Slice, reflect.Array:
		return v.Len() > 0
	default:
		return true
	}
}
