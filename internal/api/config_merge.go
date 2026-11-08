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

package api

import (
	"errors"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func mergeOutputConfigForSchema(existing, patch map[string]any, schema output.Schema) (map[string]any, error) {
	base, _ := copyConfigValue(existing).(map[string]any)
	update, _ := copyConfigValue(patch).(map[string]any)
	for _, cfg := range []map[string]any{base, update} {
		if err := normalizeSchemaKeys(cfg, schema.Fields); err != nil {
			return nil, err
		}
	}
	return mergeOutputConfig(base, update), nil
}

func normalizeSchemaKeys(cfg map[string]any, fields []output.SchemaField) error {
	for _, field := range fields {
		parts := strings.Split(field.Name, ".")
		if err := normalizeSchemaPath(cfg, parts, field.EntryFields); err != nil {
			return err
		}
		if field.Secret && field.Type == "string" {
			parts[len(parts)-1] += "_file"
			if err := normalizeSchemaPath(cfg, parts, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeSchemaPath(cfg map[string]any, parts []string, entryFields []output.SchemaField) error {
	var matched string
	var found bool
	for key := range cfg {
		if strings.EqualFold(key, parts[0]) {
			if found {
				return errors.New("ambiguous configuration: duplicate case-insensitive field names")
			}
			matched, found = key, true
		}
	}
	if !found {
		return nil
	}
	value := cfg[matched]
	delete(cfg, matched)
	cfg[parts[0]] = value
	child, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if len(parts) > 1 {
		return normalizeSchemaPath(child, parts[1:], entryFields)
	}
	if len(entryFields) > 0 {
		for _, entry := range child {
			if object, ok := entry.(map[string]any); ok {
				if err := normalizeSchemaKeys(object, entryFields); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
