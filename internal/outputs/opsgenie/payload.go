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

package opsgenie

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// Create Alert limits: https://docs.opsgenie.com/docs/alert-api#create-alert
const (
	maxMessageRunes     = 130
	maxDescriptionRunes = 15000
	maxAliasLen         = 512
	maxEntityRunes      = 512
	maxTags             = 20
	maxTagRunes         = 50
	maxDetailsRunes     = 8000
)

type alert struct {
	Details     map[string]string `json:"details,omitempty"`
	Message     string            `json:"message"`
	Alias       string            `json:"alias,omitempty"`
	Entity      string            `json:"entity,omitempty"`
	Description string            `json:"description,omitempty"`
	Priority    string            `json:"priority,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

func priority(p event.Priority) string {
	switch p {
	case event.PriorityEmergency, event.PriorityAlert:
		return "P1"
	case event.PriorityCritical:
		return "P2"
	case event.PriorityError:
		return "P3"
	case event.PriorityWarning:
		return "P4"
	default:
		return "P5"
	}
}

// buildDetails keeps keys and values together within maxDetailsRunes, as Opsgenie counts both.
func buildDetails(evt *event.Event) map[string]string {
	details := make(map[string]string, len(evt.OutputFields)+5)
	budget := maxDetailsRunes
	add := func(key, value string) bool {
		room := budget - utf8.RuneCountInString(key)
		if room <= 0 {
			return false
		}
		value = shared.TruncateRunes(value, room)
		details[key] = value
		budget = room - utf8.RuneCountInString(value)
		return budget > 0
	}
	add("source", evt.Source)
	add("rule", evt.Rule)
	add("priority", evt.Priority.String())
	if evt.Hostname != "" {
		add("hostname", evt.Hostname)
	}
	if len(evt.Tags) != 0 {
		add("tags", strings.Join(evt.Tags, ", "))
	}
	for _, key := range shared.SortMapKeys(evt.OutputFields) {
		value := evt.OutputFields[key]
		if value == nil {
			continue
		}
		if !add(strings.ReplaceAll(key, ".", "_"), fmt.Sprint(value)) {
			break
		}
	}
	return details
}

func buildAlert(evt *event.Event) alert {
	details := buildDetails(evt)

	// Opsgenie lists alerts by message, so it is the rule; entity is the affected host.
	a := alert{
		Message:     shared.TruncateRunes(evt.Rule, maxMessageRunes),
		Entity:      shared.TruncateRunes(evt.Hostname, maxEntityRunes),
		Description: shared.TruncateRunes(evt.Output, maxDescriptionRunes),
		Details:     details,
		Priority:    priority(evt.Priority),
		Tags:        alertTags(evt.Tags),
	}
	// Opsgenie deduplicates open alerts by alias, so a retry opens no second alert.
	if len(evt.UUID) <= maxAliasLen {
		a.Alias = evt.UUID
	}
	return a
}

func alertTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(tags), maxTags))
	for _, tag := range tags {
		if tag == "" {
			continue
		}
		if len(out) == maxTags {
			break
		}
		out = append(out, shared.TruncateRunes(tag, maxTagRunes))
	}
	return out
}
