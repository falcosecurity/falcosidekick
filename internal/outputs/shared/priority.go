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
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

var priorityColors = map[event.Priority]string{
	event.PriorityEmergency:     "#e20b0b",
	event.PriorityAlert:         "#ff5400",
	event.PriorityCritical:      "#ff5400",
	event.PriorityError:         "#e20b0b",
	event.PriorityWarning:       "#ffc700",
	event.PriorityNotice:        "#68c2ff",
	event.PriorityInformational: "#68c2ff",
	event.PriorityDebug:         "#ccfff2",
}

var prioritySeverity = map[string]string{
	"emergency":     "critical",
	"alert":         "critical",
	"critical":      "critical",
	"error":         "warning",
	"warning":       "warning",
	"notice":        "information",
	"informational": "information",
	"debug":         "information",
}

// PriorityColor returns the hex color code for a priority level.
// Used by rich-message outputs (Slack, Teams, Discord, Mattermost).
func PriorityColor(p event.Priority) string {
	if c, ok := priorityColors[p]; ok {
		return c
	}
	return "#cccccc"
}

// PrioritySeverity returns the collapsed severity label for a priority.
// Used by alerting outputs (Alertmanager, PagerDuty, Opsgenie).
func PrioritySeverity(p event.Priority) string {
	if s, ok := prioritySeverity[strings.ToLower(string(p))]; ok {
		return s
	}
	return "information"
}
