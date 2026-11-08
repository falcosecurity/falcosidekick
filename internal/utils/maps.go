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
	"strings"

	"github.com/mitchellh/copystructure"
)

// DeepCopyMap returns a deep copy of a map[string]any, including nested
// maps, slices, and other reference types. Falls back to returning the
// original map on copy failure.
func DeepCopyMap(m map[string]any) map[string]any {
	cp, err := copystructure.Copy(m)
	if err != nil {
		return m
	}
	return cp.(map[string]any)
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
