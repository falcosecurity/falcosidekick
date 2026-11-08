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

package datadog

import (
	"sort"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// Events API v2 limits, from the EventPayload schema.
const (
	maxTitleRunes   = 500
	maxMessageRunes = 4000
	maxTags         = 100
	maxTagRunes     = 200
	maxKeyRunes     = 100

	// source is a reserved tag in Datadog, so the Falco source gets its own key.
	sourceTag = "falco_source:"
)

// request is the Events API v2 request body for an alert event.
type request struct {
	Data data `json:"data"`
}

type data struct {
	Type       string     `json:"type"`
	Attributes attributes `json:"attributes"`
}

type attributes struct {
	Attributes     alert    `json:"attributes"`
	Title          string   `json:"title"`
	Message        string   `json:"message,omitempty"`
	Category       string   `json:"category"`
	AggregationKey string   `json:"aggregation_key,omitempty"`
	Host           string   `json:"host,omitempty"`
	Timestamp      string   `json:"timestamp"`
	Tags           []string `json:"tags"`
}

// alert holds the AlertEventCustomAttributes; custom carries the output fields, which would be high-cardinality tags.
type alert struct {
	Custom   map[string]any `json:"custom,omitempty"`
	Status   string         `json:"status"`
	Priority string         `json:"priority"`
}

// newPayload uses the event UUID as aggregation key so a retried event is deduplicated.
func newPayload(evt *event.Event) request {
	var custom map[string]any
	if len(evt.OutputFields) > 0 {
		custom = map[string]any{"output_fields": evt.OutputFields}
	}
	return request{Data: data{
		Type: "event",
		Attributes: attributes{
			Title:          shared.TruncateRunes(evt.Rule, maxTitleRunes),
			Message:        shared.TruncateRunes(evt.Output, maxMessageRunes),
			Category:       "alert",
			AggregationKey: shared.TruncateRunes(evt.UUID, maxKeyRunes),
			Host:           evt.Hostname,
			Timestamp:      evt.Time.UTC().Format(time.RFC3339Nano),
			Tags:           eventTags(evt),
			Attributes:     alert{Status: alertStatus(evt.Priority), Priority: alertPriority(evt.Priority), Custom: custom},
		},
	}}
}

// eventTags returns falco_source and the sorted rule tags within the per-event and per-tag limits.
func eventTags(evt *event.Event) []string {
	tags := make([]string, 0, len(evt.Tags)+1)
	tags = append(tags, sourceTag+evt.Source)
	falcoTags := append([]string(nil), evt.Tags...)
	sort.Strings(falcoTags)
	tags = append(tags, falcoTags...)
	if len(tags) > maxTags {
		tags = tags[:maxTags]
	}
	for i := range tags {
		tags[i] = shared.TruncateRunes(tags[i], maxTagRunes)
	}
	return tags
}

// alertStatus maps a priority to warn, error or ok, the only Events API v2 statuses.
func alertStatus(p event.Priority) string {
	switch p {
	case event.PriorityEmergency, event.PriorityAlert, event.PriorityCritical, event.PriorityError:
		return "error"
	case event.PriorityWarning:
		return "warn"
	default:
		return "ok"
	}
}

// alertPriority maps a priority to 1 (highest) through 5.
func alertPriority(p event.Priority) string {
	switch p {
	case event.PriorityEmergency, event.PriorityAlert:
		return "1"
	case event.PriorityCritical:
		return "2"
	case event.PriorityError:
		return "3"
	case event.PriorityWarning:
		return "4"
	default:
		return "5"
	}
}
