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

package pagerduty

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const (
	maxSummaryRunes = 1024
	maxDedupKeyLen  = 255
	defaultSource   = "falco"
)

type eventRequest struct {
	Payload     eventPayload `json:"payload"`
	RoutingKey  string       `json:"routing_key"`
	EventAction string       `json:"event_action"`
	DedupKey    string       `json:"dedup_key,omitempty"`
}

type eventPayload struct {
	CustomDetails map[string]any `json:"custom_details"`
	Summary       string         `json:"summary"`
	Source        string         `json:"source"`
	Severity      string         `json:"severity"`
	Timestamp     string         `json:"timestamp"`
	Component     string         `json:"component,omitempty"`
	Group         string         `json:"group,omitempty"`
	Class         string         `json:"class,omitempty"`
}

// severity maps Falco priorities to the four Events API v2 severities.
func severity(p event.Priority) string {
	switch p {
	case event.PriorityEmergency, event.PriorityAlert, event.PriorityCritical:
		return "critical"
	case event.PriorityError:
		return "error"
	case event.PriorityWarning:
		return "warning"
	default:
		return "info"
	}
}

func buildEvent(evt *event.Event, routingKey string) eventRequest {
	details := make(map[string]any, len(evt.OutputFields)+5)
	maps.Copy(details, evt.OutputFields)
	details["rule"] = evt.Rule
	details["priority"] = evt.Priority.String()
	details["source"] = evt.Source
	if evt.Hostname != "" {
		details["hostname"] = evt.Hostname
	}
	if len(evt.Tags) != 0 {
		details["tags"] = slices.Sorted(slices.Values(evt.Tags))
	}

	summary := evt.Output
	if summary == "" {
		summary = evt.Rule
	}
	source := evt.Hostname
	if source == "" {
		source = defaultSource
	}
	req := eventRequest{
		RoutingKey:  routingKey,
		EventAction: "trigger",
		Payload: eventPayload{
			Summary:       shared.TruncateRunes(summary, maxSummaryRunes),
			Source:        source,
			Severity:      severity(evt.Priority),
			Timestamp:     evt.Time.Format(time.RFC3339),
			CustomDetails: details,
			Class:         evt.Rule,
			Group:         fieldString(evt, "k8s.ns.name"),
			Component:     cmp.Or(fieldString(evt, "container.name"), fieldString(evt, "proc.name")),
		},
	}
	// Retries reuse the event UUID, so PagerDuty groups them into one alert.
	if len(evt.UUID) <= maxDedupKeyLen {
		req.DedupKey = evt.UUID
	}
	return req
}

// fieldString returns an output field as a string, or "" when it is absent or null.
func fieldString(evt *event.Event, key string) string {
	v, ok := evt.OutputFields[key]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
