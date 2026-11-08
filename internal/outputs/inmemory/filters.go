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

package inmemory

import (
	"sort"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// --- Filter helpers ---

func hasNoFilters(f *output.Filters) bool {
	return f.Filter == "" && hasNoStructuredFilters(f) && f.Since == 0
}

func hasNoStructuredFilters(f *output.Filters) bool {
	return len(f.Priority) == 0 && len(f.Rule) == 0 && len(f.Source) == 0 &&
		len(f.Hostname) == 0 && len(f.Tags) == 0
}

func matchesFreeText(e *event.Event, text string) bool {
	lower := strings.ToLower(text)
	for _, field := range []string{e.Output, e.Rule, string(e.Priority), e.Source, e.Hostname} {
		if strings.Contains(strings.ToLower(field), lower) {
			return true
		}
	}
	for _, tag := range e.Tags {
		if strings.Contains(strings.ToLower(tag), lower) {
			return true
		}
	}
	return false
}

func sortEvents(events []*event.Event, sortBy string, desc bool) {
	sort.Slice(events, func(i, j int) bool {
		var cmp int
		switch sortBy {
		case "rule":
			cmp = strings.Compare(events[i].Rule, events[j].Rule)
		case "priority":
			pi, pj := events[i].Priority.Order(), events[j].Priority.Order()
			if pi < pj {
				cmp = -1
			} else if pi > pj {
				cmp = 1
			}
		case "source":
			cmp = strings.Compare(events[i].Source, events[j].Source)
		default: // timestamp
			if events[i].Time.Before(events[j].Time) {
				cmp = -1
			} else if events[i].Time.After(events[j].Time) {
				cmp = 1
			}
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}
