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

package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// overflowValue replaces a label value once the label holds its maximum of distinct values.
const overflowValue = "other"

// labelGuard bounds the series created from event content: each label keeps at most max distinct values.
// A value seen before keeps its own series; a new value beyond the cap becomes overflowValue and is counted.
type labelGuard struct {
	seen     map[string]map[string]struct{}
	overflow *prometheus.CounterVec
	max      int
	mu       sync.Mutex
}

func newLabelGuard(maxValues int, overflow *prometheus.CounterVec) *labelGuard {
	return &labelGuard{seen: make(map[string]map[string]struct{}), overflow: overflow, max: maxValues}
}

func (g *labelGuard) value(label, value string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	values, ok := g.seen[label]
	if !ok {
		values = make(map[string]struct{})
		g.seen[label] = values
	}
	if _, known := values[value]; known {
		return value
	}
	if len(values) >= g.max {
		g.overflow.WithLabelValues(label).Inc()
		return overflowValue
	}
	values[value] = struct{}{}
	return value
}
