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

package alertmanager

import (
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// alertPayload is one alert of the Alertmanager POST /api/v2/alerts body.
type alertPayload struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     string            `json:"startsAt,omitempty"`
	EndsAt       string            `json:"endsAt,omitempty"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

func (d *driver) buildAlert(evt *event.Event) alertPayload {
	labels := map[string]string{
		"alertname": evt.Rule,
		"source":    evt.Source,
		"priority":  evt.Priority.String(),
		"severity":  d.resolveSeverity(evt.Priority),
	}

	if evt.Hostname != "" {
		labels["hostname"] = evt.Hostname
	}

	if tags := shared.FormatTags(evt.Tags, ","); tags != "" {
		labels["tags"] = tags
	}

	// Names are checked at validation; values are free text.
	for k, v := range d.cfg.ExtraLabels {
		labels[k] = v
	}

	annotations := map[string]string{
		"summary":     evt.Rule,
		"description": evt.Output,
	}
	for k, v := range d.cfg.ExtraAnnotations {
		annotations[k] = v
	}

	alert := alertPayload{
		Labels:      labels,
		Annotations: annotations,
		StartsAt:    evt.Time.UTC().Format(time.RFC3339),
	}

	if d.cfg.GeneratorURL != "" {
		alert.GeneratorURL = d.cfg.GeneratorURL
	}

	if d.cfg.ExpiresAfter > 0 {
		alert.EndsAt = evt.Time.Add(d.cfg.ExpiresAfter).UTC().Format(time.RFC3339)
	}

	return alert
}

func (d *driver) resolveSeverity(priority event.Priority) string {
	if s, ok := d.cfg.severities[priority]; ok {
		return s
	}
	return severity(priority)
}

// severity maps a priority to the monitoring-mixins severities critical, warning and info.
func severity(p event.Priority) string {
	switch p {
	case event.PriorityEmergency, event.PriorityAlert, event.PriorityCritical:
		return "critical"
	case event.PriorityError, event.PriorityWarning:
		return "warning"
	default:
		return "info"
	}
}
