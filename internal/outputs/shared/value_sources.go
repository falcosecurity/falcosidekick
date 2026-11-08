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

package shared

import (
	"fmt"
	"os"
	"reflect"
	"strings"
)

// ValueSources holds the public, secret, and file-backed values of one named
// entry in headers or query_params. Files are validated at construction and reread
// on every request with surrounding whitespace removed. Relative paths resolve from
// the process working directory.
type ValueSources struct {
	Values  []string `mapstructure:"values"`
	Secrets []string `mapstructure:"secrets"`
	Files   []string `mapstructure:"files"`
}

func decodeValueSourcesHook(_, to reflect.Type, data any) (any, error) {
	if to != reflect.TypeFor[ValueSources]() {
		return data, nil
	}
	if h, ok := data.(ValueSources); ok {
		return h, nil
	}
	raw := reflect.ValueOf(data)
	if raw.Kind() != reflect.Map {
		return nil, fmt.Errorf("entry must be a map")
	}
	var h ValueSources
	fields := []struct {
		values *[]string
		name   string
		seen   bool
	}{{&h.Values, "values", false}, {&h.Secrets, "secrets", false}, {&h.Files, "files", false}}
	iter := raw.MapRange()
	for iter.Next() {
		key, ok := iter.Key().Interface().(string)
		if !ok {
			return nil, fmt.Errorf("property names must be strings")
		}
		matched := false
		for i := range fields {
			field := &fields[i]
			if !strings.EqualFold(key, field.name) {
				continue
			}
			if field.seen {
				return nil, fmt.Errorf("duplicate property %s", field.name)
			}
			values, err := decodeStringList(iter.Value().Interface())
			if err != nil {
				return nil, fmt.Errorf("%s: %w", field.name, err)
			}
			*field.values = values
			field.seen = true
			matched = true
			break
		}
		if !matched {
			return nil, fmt.Errorf("unknown property")
		}
	}
	return h, nil
}

func decodeStringList(data any) ([]string, error) {
	switch values := data.(type) {
	case nil:
		return nil, nil
	case []string:
		return values, nil
	case []any:
		result := make([]string, len(values))
		for i, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("must be a list of strings")
			}
			result[i] = text
		}
		return result, nil
	default:
		return nil, fmt.Errorf("must be a list of strings")
	}
}

// resolveSources returns values, secrets, and trimmed file contents in that order.
// kind labels diagnostics, which never include the values. A nil valid accepts every value.
func (h ValueSources) resolveSources(kind string, valid func(string) bool) ([]string, error) {
	values := make([]string, 0, len(h.Values)+len(h.Secrets)+len(h.Files))
	for _, group := range []struct {
		name   string
		values []string
	}{{"values", h.Values}, {"secrets", h.Secrets}} {
		for i, value := range group.values {
			if valid != nil && !valid(value) {
				return nil, fmt.Errorf("%s[%d]: invalid %s value", group.name, i, kind)
			}
			values = append(values, value)
		}
	}
	for i, path := range h.Files {
		b, err := os.ReadFile(path) //nolint:gosec // secret file paths are operator-configured
		if err != nil {
			return nil, fmt.Errorf("files[%d]: cannot read %s file", i, kind)
		}
		value := strings.TrimSpace(string(b))
		if valid != nil && !valid(value) {
			return nil, fmt.Errorf("files[%d]: invalid %s value", i, kind)
		}
		values = append(values, value)
	}
	return values, nil
}
