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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// ascending lists the priorities from the lowest severity to the highest.
var ascending = []event.Priority{
	event.PriorityDebug, event.PriorityInformational, event.PriorityNotice,
	event.PriorityWarning, event.PriorityError, event.PriorityCritical,
	event.PriorityAlert, event.PriorityEmergency,
}

func TestPalette(t *testing.T) {
	tests := []struct {
		priority event.Priority
		hex      string
		rgb      int
		tone     Tone
	}{
		{event.PriorityDebug, "#9e9e9e", 0x9e9e9e, ToneNeutral},
		{event.PriorityInformational, "#68c2ff", 0x68c2ff, ToneInfo},
		{event.PriorityNotice, "#1e88e5", 0x1e88e5, ToneInfo},
		{event.PriorityWarning, "#ffc700", 0xffc700, ToneWarning},
		{event.PriorityError, "#ff8c00", 0xff8c00, ToneWarning},
		{event.PriorityCritical, "#f4511e", 0xf4511e, ToneDanger},
		{event.PriorityAlert, "#d50000", 0xd50000, ToneDanger},
		{event.PriorityEmergency, "#8b0000", 0x8b0000, ToneDanger},
		{"Warning", "#ffc700", 0xffc700, ToneWarning},
		{"unknown", "#9e9e9e", 0x9e9e9e, ToneNeutral},
	}
	for _, tc := range tests {
		t.Run(string(tc.priority), func(t *testing.T) {
			assert.Equal(t, tc.hex, PriorityColor(tc.priority))
			assert.Equal(t, tc.rgb, PriorityRGB(tc.priority))
			assert.Equal(t, tc.tone, PriorityTone(tc.priority))
		})
	}
}

func TestPaletteRisesWithSeverity(t *testing.T) {
	seen := map[int]event.Priority{}
	for i, p := range ascending {
		if other, dup := seen[PriorityRGB(p)]; dup {
			t.Errorf("%s and %s share a color", p, other)
		}
		seen[PriorityRGB(p)] = p
		if i > 0 {
			assert.GreaterOrEqual(t, PriorityTone(p), PriorityTone(ascending[i-1]), "%s is below %s", p, ascending[i-1])
		}
	}
	assert.Less(t, PriorityTone(event.PriorityError), PriorityTone(event.PriorityEmergency), "error is not as red as emergency")
}
