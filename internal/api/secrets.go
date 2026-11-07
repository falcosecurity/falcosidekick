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
	"reflect"
	"slices"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// SecretMask is the redaction sentinel rejected in explicit secret updates.
const SecretMask = "****"

type outputConfigResponse struct {
	*core.OutputConfigEntry
	SecretFields map[string]bool `json:"secret_fields,omitempty"`
}

func maskOutputConfig(entry *core.OutputConfigEntry, t output.Type) *outputConfigResponse {
	if entry == nil {
		return nil
	}
	copyEntry := *entry
	copyEntry.Config, _ = copyConfigValue(entry.Config).(map[string]any)
	masked := &outputConfigResponse{OutputConfigEntry: &copyEntry, SecretFields: make(map[string]bool)}
	visitProtectedValues(masked.Config, t, func(parent map[string]any, key string, path []string) {
		masked.SecretFields[configPointer(path)] = hasConfiguredValue(parent[key])
		delete(parent, key)
	})
	markFileSecrets(masked.Config, t.Schema.Fields, masked.SecretFields)
	return masked
}

// markFileSecrets marks a secret set through <field>_file as configured; the path itself stays visible.
func markFileSecrets(cfg map[string]any, fields []output.SchemaField, marks map[string]bool) {
	for i := range fields {
		field := &fields[i]
		if !field.HasFileVariant() {
			continue
		}
		parent, leaf := utils.NavigateMap(cfg, field.Name)
		if path, ok := parent[leaf+"_file"].(string); ok && path != "" {
			marks[configPointer(strings.Split(field.Name, "."))] = true
		}
	}
}

func maskOutputConfigs(entries map[string]*core.OutputConfigEntry, cat *catalog.Catalog) map[string]*outputConfigResponse {
	if entries == nil {
		return nil
	}
	result := make(map[string]*outputConfigResponse, len(entries))
	for name, entry := range entries {
		t, _ := cat.Get(name)
		result[name] = maskOutputConfig(entry, t)
	}
	return result
}

func maskCoreConfig(cfg *core.Config) *core.Config {
	if cfg == nil {
		return nil
	}
	return cfg.DeepCopy()
}

func containsSecretPlaceholder(cfg map[string]any, t output.Type) string {
	copyCfg, _ := copyConfigValue(cfg).(map[string]any)
	var found string
	visitProtectedValues(copyCfg, t, func(parent map[string]any, key string, path []string) {
		if containsPlaceholder(parent[key]) {
			candidate := strings.Join(path, ".")
			if found == "" || candidate < found {
				found = candidate
			}
		}
	})
	return found
}

// visitProtectedValues treats every leaf as secret when the output type is unknown.
func visitProtectedValues(cfg map[string]any, t output.Type, visit output.SecretVisitor) {
	if t.Name == "" {
		visitAllLeaves(cfg, nil, visit)
		return
	}
	output.VisitSecrets(cfg, t.Schema.Fields, visit)
}

func visitAllLeaves(cfg map[string]any, path []string, visit output.SecretVisitor) {
	for key, value := range cfg {
		next := append(slices.Clone(path), key)
		if child, ok := value.(map[string]any); ok {
			visitAllLeaves(child, next, visit)
		} else {
			visit(cfg, key, next)
		}
	}
}

func configPointer(path []string) string {
	segments := make([]string, len(path)+1)
	for i, part := range path {
		segments[i+1] = strings.ReplaceAll(strings.ReplaceAll(part, "~", "~0"), "/", "~1")
	}
	return strings.Join(segments, "/")
}

// Normalize map and slice types without JSON round-tripping numeric values.
func copyConfigValue(value any) any {
	if value == nil {
		return nil
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return value
		}
		if v.IsNil() {
			return nil
		}
		result := make(map[string]any, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			result[iter.Key().String()] = copyConfigValue(iter.Value().Interface())
		}
		return result
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return value
		}
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			clone := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
			reflect.Copy(clone, v)
			return clone.Interface()
		}
		result := make([]any, v.Len())
		for i := range result {
			result[i] = copyConfigValue(v.Index(i).Interface())
		}
		return result
	default:
		return value
	}
}

func hasConfiguredValue(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String, reflect.Map, reflect.Slice, reflect.Array:
		return v.Len() > 0
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return true
	default:
		return !v.IsZero()
	}
}

func containsPlaceholder(value any) bool {
	switch value := value.(type) {
	case string:
		return value == SecretMask
	case map[string]any:
		for _, child := range value {
			if containsPlaceholder(child) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if containsPlaceholder(child) {
				return true
			}
		}
	}
	return false
}
