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
	maxHostRunes    = 255
	// maxOutputFields bounds the custom attributes, which Datadog limits to 100 keys.
	maxOutputFields = 100

	// Datadog refuses a timestamp older than 18 hours; 17 leaves room for retries and clock skew.
	maxTimestampAge = 17 * time.Hour
	timestampLayout = "2006-01-02T15:04:05.000000Z07:00"

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
	Timestamp      string   `json:"timestamp,omitempty"`
	Tags           []string `json:"tags"`
}

// alert holds the AlertEventCustomAttributes; custom carries the output fields, which would be high-cardinality tags.
type alert struct {
	Custom   map[string]any `json:"custom,omitempty"`
	Status   string         `json:"status"`
	Priority string         `json:"priority"`
}

// newPayload uses the event UUID as aggregation key so a retried event is deduplicated. An event
// older than maxTimestampAge at now has no timestamp, so Datadog accepts it at receive time, and
// carries its time in custom.event_time.
func newPayload(evt *event.Event, now time.Time) request {
	custom := make(map[string]any, 2)
	if len(evt.OutputFields) > 0 {
		custom["output_fields"] = capOutputFields(evt.OutputFields)
	}
	timestamp := evt.Time.UTC().Format(timestampLayout)
	if now.Sub(evt.Time) > maxTimestampAge {
		custom["event_time"] = timestamp
		timestamp = ""
	}
	if len(custom) == 0 {
		custom = nil
	}
	return request{Data: data{
		Type: "event",
		Attributes: attributes{
			Title:          shared.TruncateRunes(evt.Rule, maxTitleRunes),
			Message:        shared.TruncateRunes(evt.Output, maxMessageRunes),
			Category:       "alert",
			AggregationKey: shared.TruncateRunes(evt.UUID, maxKeyRunes),
			Host:           shared.TruncateRunes(evt.Hostname, maxHostRunes),
			Timestamp:      timestamp,
			Tags:           eventTags(evt),
			Attributes:     alert{Status: alertStatus(evt.Priority), Priority: alertPriority(evt.Priority), Custom: custom},
		},
	}}
}

// capOutputFields keeps the first maxOutputFields keys in sorted order.
func capOutputFields(fields map[string]any) map[string]any {
	if len(fields) <= maxOutputFields {
		return fields
	}
	kept := make(map[string]any, maxOutputFields)
	for _, k := range shared.SortMapKeys(fields)[:maxOutputFields] {
		kept[k] = fields[k]
	}
	return kept
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
