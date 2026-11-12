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
	"slices"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// mergeOutputConfigForSchema returns the stored config and the merged config, both with schema key spelling.
func mergeOutputConfigForSchema(existing, patch map[string]any, schema output.Schema) (stored, merged map[string]any, err error) {
	base, _ := copyConfigValue(existing).(map[string]any)
	update, _ := copyConfigValue(patch).(map[string]any)
	for _, cfg := range []map[string]any{base, update} {
		if err := normalizeSchemaKeys(cfg, schema.Fields); err != nil {
			return nil, nil, err
		}
	}
	// A null on an absent key never reaches the decoder, so an unknown one is refused here as the decoder would.
	if unknown := unknownNullKeys(base, update, nil, schema.Fields); len(unknown) > 0 {
		slices.Sort(unknown)
		return nil, nil, errors.New("unknown keys: " + strings.Join(unknown, ", "))
	}
	merged = mergeOutputConfig(base, update)
	dropReplacedSecrets(merged, update, schema.Fields)
	return base, merged, nil
}

// dropReplacedSecrets removes the stored form of a secret string the patch sets in the other form:
// a new <name>_file must not lose to the stored value, nor a new value to the stored file.
func dropReplacedSecrets(merged, update map[string]any, fields []output.SchemaField) {
	for i := range fields {
		field := &fields[i]
		if !field.HasFileVariant() {
			continue
		}
		patch, leaf := utils.NavigateMap(update, field.Name)
		target, _ := utils.NavigateMap(merged, field.Name)
		if patch == nil || target == nil {
			continue
		}
		// A null or empty source in the patch clears that source; it replaces nothing.
		setsFile := utils.IsSet(patch[leaf+"_file"])
		setsValue := utils.IsSet(patch[leaf])
		switch {
		case setsFile && !setsValue:
			delete(target, leaf)
		case setsValue && !setsFile:
			delete(target, leaf+"_file")
		}
	}
}

func normalizeSchemaKeys(cfg map[string]any, fields []output.SchemaField) error {
	for i := range fields {
		field := &fields[i]
		parts := strings.Split(field.Name, ".")
		if err := normalizeSchemaPath(cfg, parts, field); err != nil {
			return err
		}
		if field.HasFileVariant() {
			parts[len(parts)-1] += "_file"
			if err := normalizeSchemaPath(cfg, parts, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// normalizeSchemaPath gives the field at parts the schema key spelling; a list for a map field is left for the decoder to refuse.
func normalizeSchemaPath(cfg map[string]any, parts []string, field *output.SchemaField) error {
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
		return normalizeSchemaPath(child, parts[1:], field)
	}
	if field != nil && len(field.EntryFields) > 0 {
		for _, entry := range child {
			if object, ok := entry.(map[string]any); ok {
				if err := normalizeSchemaKeys(object, field.EntryFields); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// unknownNullKeys returns the dotted paths of the patch's nulls that neither base holds nor the schema names.
func unknownNullKeys(base, patch map[string]any, path []string, fields []output.SchemaField) []string {
	var unknown []string
	for key, value := range patch {
		at := append(slices.Clone(path), key)
		stored, present := base[key]
		switch child := value.(type) {
		case nil:
			if !present && !schemaNames(fields, at) {
				unknown = append(unknown, strings.Join(at, "."))
			}
		case map[string]any:
			storedMap, _ := stored.(map[string]any)
			unknown = append(unknown, unknownNullKeys(storedMap, child, at, fields)...)
		}
	}
	return unknown
}

// schemaNames reports whether the schema names path: a field, a secret's <name>_file, an object of fields, or a map entry.
func schemaNames(fields []output.SchemaField, path []string) bool {
	for i := range fields {
		field := &fields[i]
		parts := strings.Split(field.Name, ".")
		if field.HasFileVariant() && len(path) == len(parts) && hasPrefixFold(path[:len(path)-1], parts[:len(parts)-1]) &&
			strings.EqualFold(path[len(path)-1], parts[len(parts)-1]+"_file") {
			return true
		}
		if len(path) <= len(parts) {
			if hasPrefixFold(parts, path) {
				return true
			}
			continue
		}
		if !field.IsMap() || !hasPrefixFold(path, parts) {
			continue
		}
		rest := path[len(parts)+1:]
		if len(rest) == 0 || schemaNames(field.EntryFields, rest) {
			return true
		}
	}
	return false
}

func hasPrefixFold(s, prefix []string) bool {
	if len(prefix) > len(s) {
		return false
	}
	for i := range prefix {
		if !strings.EqualFold(s[i], prefix[i]) {
			return false
		}
	}
	return true
}
