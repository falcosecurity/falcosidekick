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
	"maps"
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
		_, setsFile := patch[leaf+"_file"]
		_, setsValue := patch[leaf]
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

// normalizeSchemaPath gives the field at parts the schema key spelling and turns a map field
// written as a list into the object the output decoder makes of it.
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
	if list, isList := value.([]any); isList && len(parts) == 1 && field.IsMap() {
		if object, ok := mapFromList(list); ok {
			value = object
		}
	}
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

// mapFromList merges a list into one object as the output decoder does with a list given for a
// map: elements in order, later keys win, nested lists flattened, nil elements skipped. ok is false
// for any other element, which the decoder rejects.
func mapFromList(list []any) (object map[string]any, ok bool) {
	object = make(map[string]any)
	for _, item := range list {
		switch item := item.(type) {
		case nil:
		case map[string]any:
			maps.Copy(object, item)
		case []any:
			nested, ok := mapFromList(item)
			if !ok {
				return nil, false
			}
			maps.Copy(object, nested)
		default:
			return nil, false
		}
	}
	return object, true
}
