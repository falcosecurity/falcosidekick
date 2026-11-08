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

package reload

import (
	"bytes"
	"encoding/json"
)

// DiffResult holds the three sets produced by comparing old vs new output configs.
type DiffResult struct {
	Added   map[string]map[string]any // output name -> new config
	Changed map[string]map[string]any // output name -> new config
	Removed []string                  // output names no longer present
}

// IsEmpty returns true when no outputs were added, changed, or removed.
func (d DiffResult) IsEmpty() bool {
	return len(d.Added) == 0 && len(d.Changed) == 0 && len(d.Removed) == 0
}

// DiffOutputConfigs compares old and new output config maps by output name.
// Config equality uses JSON serialization with sorted keys so that nested map
// order does not cause false positives.
func DiffOutputConfigs(old, updated map[string]map[string]any) DiffResult {
	result := DiffResult{
		Added:   make(map[string]map[string]any),
		Changed: make(map[string]map[string]any),
	}

	for name, newCfg := range updated {
		oldCfg, exists := old[name]
		if !exists {
			result.Added[name] = newCfg
			continue
		}
		if !configEqual(oldCfg, newCfg) {
			result.Changed[name] = newCfg
		}
	}

	for name := range old {
		if _, exists := updated[name]; !exists {
			result.Removed = append(result.Removed, name)
		}
	}

	return result
}

func configEqual(a, b map[string]any) bool {
	aj, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aj, bj)
}
