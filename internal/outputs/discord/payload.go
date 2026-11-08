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

package discord

import (
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// Discord rejects an embed over these limits: https://docs.discord.com/developers/resources/message
const (
	maxTitleRunes       = 256
	maxDescriptionRunes = 4096
	maxFields           = 25
	maxFieldNameRunes   = 256
	maxFieldValueRunes  = 1024
	maxEmbedRunes       = 6000
	codeFence           = "```"
)

type payload struct {
	AvatarURL string  `json:"avatar_url,omitempty"`
	Embeds    []embed `json:"embeds"`
}

type embed struct {
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	Timestamp   string  `json:"timestamp"`
	Fields      []field `json:"fields"`
	Color       int     `json:"color"`
}

type field struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

func newField(name, value string) field {
	return field{
		Name:   shared.TruncateRunes(name, maxFieldNameRunes),
		Value:  shared.TruncateRunes(value, maxFieldValueRunes),
		Inline: true,
	}
}

func (f field) runes() int {
	return utf8.RuneCountInString(f.Name) + utf8.RuneCountInString(f.Value)
}

// buildPayload drops output fields first, then shortens the description, when the embed would exceed a limit.
func (d *driver) buildPayload(evt *event.Event) payload {
	title := shared.TruncateRunes(evt.Rule, maxTitleRunes)
	head := []field{
		newField("rule", evt.Rule),
		newField("priority", evt.Priority.String()),
		newField("source", evt.Source),
	}
	if evt.Hostname != "" {
		head = append(head, newField("hostname", evt.Hostname))
	}
	var tail []field
	if tags := shared.FormatTags(evt.Tags, ", "); tags != "" {
		tail = append(tail, newField("tags", tags))
	}

	description := shared.TruncateRunes(evt.Output, maxDescriptionRunes)
	budget := maxEmbedRunes - utf8.RuneCountInString(title) - utf8.RuneCountInString(description)
	for _, f := range head {
		budget -= f.runes()
	}
	for _, f := range tail {
		budget -= f.runes()
	}
	if budget < 0 {
		description = shared.TruncateRunes(description, max(utf8.RuneCountInString(description)+budget, 0))
		budget = 0
	}

	fields := head
	slots := maxFields - len(head) - len(tail)
	keys := shared.SortMapKeys(evt.OutputFields)
	for i, k := range keys {
		value := shared.TruncateRunes(fmt.Sprintf("%v", evt.OutputFields[k]), maxFieldValueRunes-2*len(codeFence))
		f := newField(k, codeFence+value+codeFence)
		if slots == 0 || f.runes() > budget {
			d.logger.Warn("embed limit reached, remaining output fields dropped",
				"max_fields", maxFields, "max_characters", maxEmbedRunes, "dropped", len(keys)-i)
			break
		}
		fields = append(fields, f)
		slots--
		budget -= f.runes()
	}
	fields = append(fields, tail...)

	return payload{
		AvatarURL: d.cfg.AvatarURL,
		Embeds: []embed{{
			Title:       title,
			Description: description,
			Timestamp:   evt.Time.UTC().Format(time.RFC3339Nano),
			Color:       shared.PriorityRGB(evt.Priority),
			Fields:      fields,
		}},
	}
}
