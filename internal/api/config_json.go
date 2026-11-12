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
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// durationsAsStrings returns v for encoding/json with every time.Duration as a Go duration string
// ("30s"); structs become maps under their json names with omitempty and embedding honored.
func durationsAsStrings(v any) any {
	return durationValue(reflect.ValueOf(v))
}

var (
	durationType  = reflect.TypeFor[time.Duration]()
	marshalerType = reflect.TypeFor[json.Marshaler]()
)

func durationValue(v reflect.Value) any {
	if !v.IsValid() {
		return nil
	}
	if v.Type() == durationType {
		return utils.FormatDuration(time.Duration(v.Int()))
	}
	if v.Type().Implements(marshalerType) {
		return v.Interface()
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return durationValue(v.Elem())
	case reflect.Struct:
		object := make(map[string]any)
		structFields(v, object)
		return object
	default:
		return v.Interface()
	}
}

func structFields(v reflect.Value, object map[string]any) {
	for i := range v.NumField() {
		field := v.Type().Field(i)
		value := v.Field(i)
		name, opts, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" && opts == "" {
			continue
		}
		if field.Anonymous && name == "" {
			if value.Kind() == reflect.Pointer {
				if value.IsNil() {
					continue
				}
				value = value.Elem()
			}
			if value.Kind() == reflect.Struct {
				structFields(value, object)
				continue
			}
		}
		if !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		if strings.Contains(","+opts+",", ",omitempty,") && isEmptyJSONValue(value) {
			continue
		}
		object[name] = durationValue(value)
	}
}

// isEmptyJSONValue is encoding/json's omitempty test.
func isEmptyJSONValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Interface, reflect.Pointer:
		return v.IsZero()
	default:
		return false
	}
}
