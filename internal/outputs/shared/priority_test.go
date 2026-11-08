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

func TestPriorityColorCoversAllPriorities(t *testing.T) {
	priorities := []event.Priority{
		event.PriorityDebug, event.PriorityInformational, event.PriorityNotice,
		event.PriorityWarning, event.PriorityError, event.PriorityCritical,
		event.PriorityAlert, event.PriorityEmergency,
	}
	for _, p := range priorities {
		t.Run(string(p), func(t *testing.T) {
			color := PriorityColor(p)
			assert.NotEmpty(t, color, "priority %s must produce a color", p)
			assert.Regexp(t, `^#[0-9a-f]{6}$`, color, "color must be a valid hex code")
		})
	}
}

func TestPriorityColorUnknownFallback(t *testing.T) {
	color := PriorityColor(event.Priority("nonexistent"))
	assert.Equal(t, "#cccccc", color)
}

func TestPrioritySeverityCoversAllPriorities(t *testing.T) {
	priorities := []event.Priority{
		event.PriorityDebug, event.PriorityInformational, event.PriorityNotice,
		event.PriorityWarning, event.PriorityError, event.PriorityCritical,
		event.PriorityAlert, event.PriorityEmergency,
	}
	for _, p := range priorities {
		t.Run(string(p), func(t *testing.T) {
			sev := PrioritySeverity(p)
			assert.NotEmpty(t, sev, "priority %s must produce a severity", p)
			assert.Contains(t, []string{"critical", "warning", "information"}, sev)
		})
	}
}

func TestPrioritySeverityUnknownFallback(t *testing.T) {
	sev := PrioritySeverity(event.Priority("nonexistent"))
	assert.Equal(t, "information", sev)
}

func TestPrioritySeverityCaseInsensitive(t *testing.T) {
	assert.Equal(t, PrioritySeverity("Warning"), PrioritySeverity("warning"))
	assert.Equal(t, PrioritySeverity("CRITICAL"), PrioritySeverity("critical"))
}
