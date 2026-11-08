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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func TestHasNoFilters(t *testing.T) {
	assert.True(t, hasNoFilters(&output.Filters{}))
	assert.False(t, hasNoFilters(&output.Filters{Priority: []string{"warning"}}))
	assert.False(t, hasNoFilters(&output.Filters{Since: time.Hour}))
}

func TestHasNoStructuredFilters(t *testing.T) {
	assert.True(t, hasNoStructuredFilters(&output.Filters{}))
	assert.True(t, hasNoStructuredFilters(&output.Filters{Since: time.Hour}))
	assert.False(t, hasNoStructuredFilters(&output.Filters{Rule: []string{"test"}}))
}

func TestMatchesFreeText(t *testing.T) {
	evt := &event.Event{
		Rule:     "Write to /etc",
		Output:   "file write detected",
		Priority: event.PriorityWarning,
		Source:   "syscall",
		Hostname: "node-1",
		Tags:     []string{"filesystem", "security"},
	}

	assert.True(t, matchesFreeText(evt, "write"))
	assert.True(t, matchesFreeText(evt, "WRITE"))
	assert.True(t, matchesFreeText(evt, "node-1"))
	assert.True(t, matchesFreeText(evt, "filesystem"))
	assert.False(t, matchesFreeText(evt, "nonexistent"))
}

func TestSortEventsTimestamp(t *testing.T) {
	now := time.Now()
	events := []*event.Event{
		{Time: now.Add(2 * time.Second)},
		{Time: now},
		{Time: now.Add(time.Second)},
	}

	sortEvents(events, "timestamp", true)
	assert.True(t, events[0].Time.After(events[2].Time), "desc: newest first")

	sortEvents(events, "timestamp", false)
	assert.True(t, events[0].Time.Before(events[2].Time), "asc: oldest first")
}

func TestSortEventsRule(t *testing.T) {
	events := []*event.Event{
		{Rule: "ZZZ"},
		{Rule: "AAA"},
		{Rule: "MMM"},
	}

	sortEvents(events, "rule", false)
	assert.Equal(t, "AAA", events[0].Rule)
	assert.Equal(t, "ZZZ", events[2].Rule)
}

func TestSortEventsPriority(t *testing.T) {
	events := []*event.Event{
		{Priority: event.PriorityDebug},
		{Priority: event.PriorityEmergency},
		{Priority: event.PriorityWarning},
	}

	sortEvents(events, "priority", true)
	assert.Equal(t, event.PriorityEmergency, events[0].Priority)
	assert.Equal(t, event.PriorityDebug, events[2].Priority)
}
