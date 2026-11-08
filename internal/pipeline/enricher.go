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

package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/google/uuid"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

const (
	truncateFieldSuffix = "[...]"
	defaultHostname     = "unknown"
)

// Enricher adds custom fields, tags, UUID, and applies transformations to events.
type Enricher struct {
	templatedFields map[string]*template.Template
	cfg             output.EnricherConfig
}

// NewEnricher creates an Enricher from configuration.
func NewEnricher(cfg output.EnricherConfig) (*Enricher, error) {
	templates := make(map[string]*template.Template, len(cfg.TemplatedFields))
	for k, v := range cfg.TemplatedFields {
		tmpl, err := template.New(k).Parse(v)
		if err != nil {
			return nil, fmt.Errorf("enricher: parse template %q: %w", k, err)
		}
		templates[k] = tmpl
	}

	return &Enricher{
		cfg:             cfg,
		templatedFields: templates,
	}, nil
}

// Enrich applies all enrichment steps to the evt in place.
func (e *Enricher) Enrich(evt *event.Event) error {
	evt.UUID = uuid.NewString()

	e.injectCustomFields(evt)
	e.evaluateTemplatedFields(evt)
	e.injectCustomTags(evt)
	e.applyDefaultHostname(evt)
	e.replaceBrackets(evt)
	e.truncateIfNeeded(evt)

	return nil
}

func (e *Enricher) injectCustomFields(evt *event.Event) {
	for k, v := range e.cfg.CustomFields {
		evt.OutputFields[k] = v
	}
}

func (e *Enricher) evaluateTemplatedFields(evt *event.Event) {
	for k, tmpl := range e.templatedFields {
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, evt.OutputFields); err != nil {
			continue
		}
		evt.OutputFields[k] = buf.String()
	}
}

func (e *Enricher) injectCustomTags(evt *event.Event) {
	if len(e.cfg.CustomTags) == 0 {
		return
	}
	evt.Tags = append(evt.Tags, e.cfg.CustomTags...)
	sort.Strings(evt.Tags)
}

func (e *Enricher) applyDefaultHostname(evt *event.Event) {
	if evt.Hostname == "" {
		evt.Hostname = defaultHostname
	}
}

func (e *Enricher) replaceBrackets(evt *event.Event) {
	if e.cfg.BracketReplacer == "" {
		return
	}
	replacer := strings.NewReplacer("[", e.cfg.BracketReplacer, "]", e.cfg.BracketReplacer)
	replaced := make(map[string]interface{}, len(evt.OutputFields))
	for k, v := range evt.OutputFields {
		replaced[replacer.Replace(k)] = v
	}
	evt.OutputFields = replaced
}

func (e *Enricher) truncateIfNeeded(evt *event.Event) {
	if e.cfg.TruncateEventThreshold <= 0 || e.cfg.TruncateFieldThreshold <= len(truncateFieldSuffix) {
		return
	}
	data, err := json.Marshal(evt)
	if err != nil || len(data) <= e.cfg.TruncateEventThreshold {
		return
	}
	for k, v := range evt.OutputFields {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if len(s) > e.cfg.TruncateFieldThreshold {
			evt.OutputFields[k] = s[:e.cfg.TruncateFieldThreshold-len(truncateFieldSuffix)] + truncateFieldSuffix
		}
	}
}
