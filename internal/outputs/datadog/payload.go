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
	"fmt"
	"sort"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const (
	sourceTypeName = "falco"
	// The Events API v1 limits text to 4000 characters.
	maxTextRunes = 4000

	alertError   = "error"
	alertWarning = "warning"
	alertInfo    = "info"
)

// payload is the Events API v1 request body.
type payload struct {
	Title      string   `json:"title"`
	Text       string   `json:"text"`
	AlertType  string   `json:"alert_type"`
	SourceType string   `json:"source_type_name"`
	Tags       []string `json:"tags"`
}

func newPayload(evt *event.Event) payload {
	tags := make([]string, 0, len(evt.OutputFields)+len(evt.Tags)+3)
	for _, key := range shared.SortMapKeys(evt.OutputFields) {
		tags = append(tags, fmt.Sprintf("%v:%v", key, evt.OutputFields[key]))
	}
	tags = append(tags, "source:"+evt.Source, "source:falco")
	if evt.Hostname != "" {
		tags = append(tags, "hostname:"+evt.Hostname)
	}
	falcoTags := append([]string(nil), evt.Tags...)
	sort.Strings(falcoTags)
	tags = append(tags, falcoTags...)

	return payload{
		Title:      evt.Rule,
		Text:       shared.TruncateRunes(evt.Output, maxTextRunes),
		AlertType:  alertType(evt.Priority),
		SourceType: sourceTypeName,
		Tags:       tags,
	}
}

// Events API v2 limits, from the EventPayload schema.
const (
	maxTitleRunes = 500
	maxTags       = 100
	maxTagRunes   = 200
	maxKeyRunes   = 100
)

// v2Request is the Events API v2 request body for an alert event.
type v2Request struct {
	Data v2Data `json:"data"`
}

type v2Data struct {
	Type       string      `json:"type"`
	Attributes v2Attribute `json:"attributes"`
}

type v2Attribute struct {
	Attributes     v2Alert  `json:"attributes"`
	Title          string   `json:"title"`
	Message        string   `json:"message,omitempty"`
	Category       string   `json:"category"`
	AggregationKey string   `json:"aggregation_key,omitempty"`
	Timestamp      string   `json:"timestamp"`
	Tags           []string `json:"tags"`
}

type v2Alert struct {
	Status   string `json:"status"`
	Priority string `json:"priority"`
}

// newV2Payload uses the event UUID as aggregation key so a retried event is deduplicated.
func newV2Payload(evt *event.Event) v2Request {
	v1 := newPayload(evt)
	tags := v1.Tags
	if len(tags) > maxTags {
		tags = tags[:maxTags]
	}
	for i := range tags {
		tags[i] = shared.TruncateRunes(tags[i], maxTagRunes)
	}
	return v2Request{Data: v2Data{
		Type: "event",
		Attributes: v2Attribute{
			Title:          shared.TruncateRunes(evt.Rule, maxTitleRunes),
			Message:        v1.Text,
			Category:       "alert",
			AggregationKey: shared.TruncateRunes(evt.UUID, maxKeyRunes),
			Timestamp:      evt.Time.UTC().Format(time.RFC3339Nano),
			Tags:           tags,
			Attributes:     v2Alert{Status: alertStatus(evt.Priority), Priority: alertPriority(evt.Priority)},
		},
	}}
}

// alertStatus maps a priority to warn, error or ok, the only Events API v2 statuses.
func alertStatus(p event.Priority) string {
	switch alertType(p) {
	case alertError:
		return "error"
	case alertWarning:
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

func alertType(p event.Priority) string {
	switch p {
	case event.PriorityEmergency, event.PriorityAlert, event.PriorityCritical, event.PriorityError:
		return alertError
	case event.PriorityWarning:
		return alertWarning
	default:
		return alertInfo
	}
}
