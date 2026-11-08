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

package catalog

import (
	"fmt"
	"sync"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// Catalog holds all known output types.
type Catalog struct {
	types map[string]output.Type
	mu    sync.RWMutex
}

// New creates a Catalog from an explicit list of output types.
func New(types []output.Type) (*Catalog, error) {
	if len(types) == 0 {
		return nil, fmt.Errorf("catalog: at least one output type required")
	}

	c := &Catalog{types: make(map[string]output.Type, len(types))}
	for _, t := range types {
		if t.Name == "" {
			return nil, fmt.Errorf("catalog: output type with empty name")
		}
		if t.New == nil {
			return nil, fmt.Errorf("catalog: output type %q has nil constructor", t.Name)
		}
		if _, exists := c.types[t.Name]; exists {
			return nil, fmt.Errorf("catalog: duplicate output type %q", t.Name)
		}
		c.types[t.Name] = t
	}
	return c, nil
}

// Get returns an output type by name.
func (c *Catalog) Get(name string) (output.Type, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.types[name]
	return t, ok
}

// All returns all known output types.
func (c *Catalog) All() []output.Type {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]output.Type, 0, len(c.types))
	for _, t := range c.types {
		result = append(result, t)
	}
	return result
}

// Create instantiates a configured output by name.
func (c *Catalog) Create(name string, cfg map[string]any, deps output.Deps) (output.Driver, error) {
	t, ok := c.Get(name)
	if !ok {
		return nil, fmt.Errorf("catalog: unknown output type %q", name)
	}
	driver, err := t.New(cfg, deps)
	if err != nil {
		return nil, fmt.Errorf("catalog: create %q: %w", name, err)
	}
	return driver, nil
}

// Names returns the names of all known output types.
func (c *Catalog) Names() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, 0, len(c.types))
	for name := range c.types {
		names = append(names, name)
	}
	return names
}
