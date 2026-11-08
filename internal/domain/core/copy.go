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

package core

import "github.com/falcosecurity/falcosidekick/internal/utils"

// DeepCopy returns a deep copy of c.
func (c *Config) DeepCopy() *Config {
	cp := *c
	if c.TLS != nil {
		tlsCopy := *c.TLS
		cp.TLS = &tlsCopy
	}
	return &cp
}

// DeepCopy returns a deep copy of e.
func (e OutputConfigEntry) DeepCopy() *OutputConfigEntry {
	cp := e
	cp.Config = utils.DeepCopyMap(e.Config)
	return &cp
}

// DeepCopy returns a deep copy of e.
func (e *ConfigEntry) DeepCopy() *ConfigEntry {
	cp := *e
	if e.Config != nil {
		cp.Config = e.Config.DeepCopy()
	}
	return &cp
}

// DeepCopy returns a deep copy of l.
func (l *PipelineLayout) DeepCopy() *PipelineLayout {
	cp := *l
	if l.Nodes != nil {
		cp.Nodes = make([]LayoutNode, len(l.Nodes))
		copy(cp.Nodes, l.Nodes)
	}
	return &cp
}
