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

package utils

import (
	"reflect"
	"strings"
)

// DeepCopyMap returns a copy of m that shares no map or slice with it.
func DeepCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = deepCopyValue(v)
	}
	return cp
}

func deepCopyValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		return DeepCopyMap(typed)
	case []any:
		cp := make([]any, len(typed))
		for i, item := range typed {
			cp[i] = deepCopyValue(item)
		}
		return cp
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() {
			return v
		}
		cp := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		for iter := rv.MapRange(); iter.Next(); {
			cp.SetMapIndex(iter.Key(), copyReflected(iter.Value(), rv.Type().Elem()))
		}
		return cp.Interface()
	case reflect.Slice:
		if rv.IsNil() {
			return v
		}
		cp := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := range rv.Len() {
			cp.Index(i).Set(copyReflected(rv.Index(i), rv.Type().Elem()))
		}
		return cp.Interface()
	default:
		return v
	}
}

func copyReflected(v reflect.Value, elem reflect.Type) reflect.Value {
	if !v.IsValid() || (v.Kind() == reflect.Interface && v.IsNil()) {
		return reflect.Zero(elem)
	}
	return reflect.ValueOf(deepCopyValue(v.Interface())).Convert(elem)
}

// NavigateMap traverses a nested map by dot-separated path segments and
// returns the parent map containing the leaf key, plus the leaf key.
// For "auth.password" with cfg["auth"] a map, returns (authMap, "password").
// For "password", returns (cfg, "password"). Returns (nil, "") if any
// intermediate segment is missing or not a map.
func NavigateMap(m map[string]any, path string) (parent map[string]any, leafKey string) {
	parts := strings.Split(path, ".")
	current := m
	for i := 0; i < len(parts)-1; i++ {
		child, ok := current[parts[i]]
		if !ok {
			return nil, ""
		}
		childMap, ok := child.(map[string]any)
		if !ok {
			return nil, ""
		}
		current = childMap
	}
	return current, parts[len(parts)-1]
}

// DeepMergeMap recursively merges src into dst. Maps recurse; scalars overwrite.
func DeepMergeMap(dst, src map[string]any) {
	for key, srcVal := range src {
		dstVal, exists := dst[key]
		if !exists {
			dst[key] = srcVal
			continue
		}
		srcMap, srcOK := srcVal.(map[string]any)
		dstMap, dstOK := dstVal.(map[string]any)
		if srcOK && dstOK {
			DeepMergeMap(dstMap, srcMap)
		} else {
			dst[key] = srcVal
		}
	}
}

// DropNulls removes the nil-valued keys of m at every depth, in place; lists are kept as they are.
func DropNulls(m map[string]any) {
	for key, value := range m {
		if value == nil {
			delete(m, key)
			continue
		}
		dropNullsIn(value)
	}
}

func dropNullsIn(value any) {
	switch typed := value.(type) {
	case map[string]any:
		DropNulls(typed)
	case []any:
		for _, item := range typed {
			dropNullsIn(item)
		}
	}
}

// MergePatch applies patch to dst in place as an RFC 7386 JSON merge patch; patch is not retained.
func MergePatch(dst, patch map[string]any) {
	for key, value := range patch {
		if value == nil {
			delete(dst, key)
			continue
		}
		if object, ok := value.(map[string]any); ok {
			target, isMap := dst[key].(map[string]any)
			if !isMap {
				target = make(map[string]any, len(object))
				dst[key] = target
			}
			MergePatch(target, object)
			continue
		}
		copied := deepCopyValue(value)
		dropNullsIn(copied)
		dst[key] = copied
	}
}

// IsSet reports whether a raw config value counts as set: not null and not the empty string.
func IsSet(value any) bool { return value != nil && value != "" }
