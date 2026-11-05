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

package teams

import (
	"encoding/json"
	"fmt"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// Envelope and limits from
// https://learn.microsoft.com/en-us/connectors/teams/ (When a Teams webhook request is received) and
// https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook.
const (
	adaptiveContentType = "application/vnd.microsoft.card.adaptive"
	adaptiveSchema      = "http://adaptivecards.io/schemas/adaptive-card.json"
	// Container styles good/attention/warning/accent need 1.2; Teams renders up to 1.6.
	adaptiveVersion = "1.4"
	cardTitle       = "Falcosidekick"
	// Teams rejects messages above 28 KB; the margin covers what the flow adds.
	maxPayloadBytes = 27 * 1024
	maxTextRunes    = 16 * 1024
	maxFactRunes    = 1024
)

type message struct {
	Type        string       `json:"type"`
	Attachments []attachment `json:"attachments"`
}

type attachment struct {
	ContentURL  *string      `json:"contentUrl"`
	ContentType string       `json:"contentType"`
	Content     adaptiveCard `json:"content"`
}

type adaptiveCard struct {
	MSTeams map[string]string `json:"msteams,omitempty"`
	Schema  string            `json:"$schema"`
	Type    string            `json:"type"`
	Version string            `json:"version"`
	Body    []element         `json:"body"`
}

// element is one Adaptive Card body element; unused properties are omitted.
type element struct {
	Wrap     *bool     `json:"wrap,omitempty"`
	IsSubtle *bool     `json:"isSubtle,omitempty"`
	Bleed    *bool     `json:"bleed,omitempty"`
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	Weight   string    `json:"weight,omitempty"`
	Size     string    `json:"size,omitempty"`
	Color    string    `json:"color,omitempty"`
	Spacing  string    `json:"spacing,omitempty"`
	Style    string    `json:"style,omitempty"`
	URL      string    `json:"url,omitempty"`
	AltText  string    `json:"altText,omitempty"`
	Width    string    `json:"width,omitempty"`
	Items    []element `json:"items,omitempty"`
	Columns  []element `json:"columns,omitempty"`
	Facts    []fact    `json:"facts,omitempty"`
}

type fact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

// priorityStyles maps priorities to Adaptive Card container styles, following
// the v2 MessageCard hues: red/orange, yellow, green, blue, neutral.
var priorityStyles = map[event.Priority]string{
	event.PriorityEmergency:     "attention",
	event.PriorityAlert:         "attention",
	event.PriorityCritical:      "attention",
	event.PriorityError:         "warning",
	event.PriorityWarning:       "warning",
	event.PriorityNotice:        "good",
	event.PriorityInformational: "accent",
	event.PriorityDebug:         "default",
}

// priorityStyle returns a value valid both as a Container style and as a
// TextBlock color.
func priorityStyle(p event.Priority) string {
	if s, ok := priorityStyles[p]; ok {
		return s
	}
	return "default"
}

func ptr[T any](v T) *T { return &v }

// factBytes is the encoded size of f in a facts array, separator included.
func factBytes(f fact) int {
	b, _ := json.Marshal(f)
	return len(b) + 1
}

// buildFacts returns the v2 fact order: rule, priority, source, hostname,
// output fields sorted by key, tags. Output fields are facts[outputFrom:outputTo],
// so callers can drop them before the others.
func buildFacts(evt *event.Event) (facts []fact, outputFrom, outputTo int) {
	facts = append(facts,
		fact{Title: "rule", Value: shared.TruncateRunes(evt.Rule, maxFactRunes)},
		fact{Title: "priority", Value: string(evt.Priority)},
		fact{Title: "source", Value: shared.TruncateRunes(evt.Source, maxFactRunes)},
	)
	if evt.Hostname != "" {
		facts = append(facts, fact{Title: "hostname", Value: shared.TruncateRunes(evt.Hostname, maxFactRunes)})
	}
	outputFrom = len(facts)
	for _, k := range shared.SortMapKeys(evt.OutputFields) {
		facts = append(facts, fact{
			Title: shared.TruncateRunes(k, maxFactRunes),
			Value: shared.TruncateRunes(fmt.Sprintf("%v", evt.OutputFields[k]), maxFactRunes),
		})
	}
	outputTo = len(facts)
	if tags := shared.FormatTags(evt.Tags, ", "); tags != "" {
		facts = append(facts, fact{Title: "tags", Value: shared.TruncateRunes(tags, maxFactRunes)})
	}
	return facts, outputFrom, outputTo
}

func (d *driver) card(evt *event.Event, text string, facts []fact) message {
	style := priorityStyle(evt.Priority)
	heading := []element{
		{Type: "TextBlock", Text: cardTitle, Weight: "bolder", Size: "medium", Wrap: ptr(true)},
		{Type: "TextBlock", Text: evt.Time.String(), Spacing: "none", IsSubtle: ptr(true), Wrap: ptr(true)},
		{Type: "TextBlock", Text: string(evt.Priority), Spacing: "none", Weight: "bolder", Color: style, Wrap: ptr(true)},
	}
	header := element{Type: "Container", Style: style, Bleed: ptr(true), Items: heading}
	if d.cfg.ActivityImage != "" {
		header.Items = []element{{Type: "ColumnSet", Columns: []element{
			{Type: "Column", Width: "auto", Items: []element{
				{Type: "Image", URL: d.cfg.ActivityImage, Size: "small", AltText: cardTitle},
			}},
			{Type: "Column", Width: "stretch", Items: heading},
		}}}
	}
	body := []element{header}
	if text != "" {
		body = append(body, element{Type: "TextBlock", Text: text, Wrap: ptr(true)})
	}
	if len(facts) > 0 {
		body = append(body, element{Type: "FactSet", Facts: facts})
	}
	return message{
		Type: "message",
		Attachments: []attachment{{
			ContentType: adaptiveContentType,
			Content: adaptiveCard{
				Schema:  adaptiveSchema,
				Type:    "AdaptiveCard",
				Version: adaptiveVersion,
				MSTeams: map[string]string{"width": "Full"},
				Body:    body,
			},
		}},
	}
}

// buildPayload renders the card and shrinks it under maxPayloadBytes: output
// fields go first, then the other facts, then the text is cut.
func (d *driver) buildPayload(evt *event.Event) ([]byte, error) {
	var text string
	if d.cfg.OutputFormat == formatAll || d.cfg.OutputFormat == formatText {
		text = shared.TruncateRunes(evt.Output, maxTextRunes)
	}
	var facts []fact
	outputFrom, outputTo := 0, 0
	if d.cfg.OutputFormat == formatAll || d.cfg.OutputFormat == formatFields {
		facts, outputFrom, outputTo = buildFacts(evt)
	}
	total := len(facts)
	for {
		body, err := json.Marshal(d.card(evt, text, facts))
		if err != nil {
			return nil, err
		}
		excess := len(body) - maxPayloadBytes
		if excess <= 0 {
			if dropped := total - len(facts); dropped > 0 {
				d.logger.Warn("card size limit reached, facts dropped", "limit_bytes", maxPayloadBytes, "dropped", dropped)
			}
			return body, nil
		}
		switch {
		case outputTo > outputFrom:
			cut := outputTo
			for freed := 0; cut > outputFrom && freed < excess; cut-- {
				freed += factBytes(facts[cut-1])
			}
			facts = append(facts[:cut], facts[outputTo:]...)
			outputTo = cut
		case len(facts) > 0:
			facts = facts[:len(facts)-1]
		case text != "":
			text = shared.TruncateBytes(text, max(len(text)-excess, 0))
		default:
			return nil, fmt.Errorf("card exceeds %d bytes", maxPayloadBytes)
		}
	}
}
