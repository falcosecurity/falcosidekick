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

package slack

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// Block Kit limits: https://docs.slack.dev/reference/block-kit/blocks
const (
	maxHeaderRunes      = 150
	maxSectionRunes     = 3000
	maxFieldRunes       = 2000
	maxFieldsPerSection = 10
	maxFooterRunes      = 300
	// maxFields keeps the message at a dozen blocks, far under the 50 Slack accepts.
	maxFields     = 100
	maxTitleRunes = 200
)

type slackPayload struct {
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments"`
}

// slackAttachment carries the blocks so that the priority color stays as the side bar.
type slackAttachment struct {
	Color    string  `json:"color"`
	Fallback string  `json:"fallback"`
	Blocks   []block `json:"blocks"`
}

type block struct {
	Text     *textObject  `json:"text,omitempty"`
	Type     string       `json:"type"`
	Fields   []textObject `json:"fields,omitempty"`
	Elements []textObject `json:"elements,omitempty"`
}

type textObject struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// mrkdwnEscaper escapes the characters Slack reserves for links and mentions.
var mrkdwnEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// escapeMrkdwn escapes s and cuts it to maxRunes without splitting an escape sequence.
func escapeMrkdwn(s string, maxRunes int) string {
	escaped := mrkdwnEscaper.Replace(s)
	if utf8.RuneCountInString(escaped) <= maxRunes {
		return escaped
	}
	const marker = "..."
	var b strings.Builder
	n := 0
	for _, r := range s {
		e := mrkdwnEscaper.Replace(string(r))
		if n+utf8.RuneCountInString(e) > maxRunes-len(marker) {
			break
		}
		_, _ = b.WriteString(e)
		n += utf8.RuneCountInString(e)
	}
	return b.String() + marker
}

func mrkdwn(text string) textObject { return textObject{Type: "mrkdwn", Text: text} }

func fieldText(title, value string) string {
	head := "*" + escapeMrkdwn(title, maxTitleRunes) + "*\n"
	return head + escapeMrkdwn(value, maxFieldRunes-utf8.RuneCountInString(head))
}

// slackDate renders t in the reader's time zone, with RFC 3339 for clients that cannot.
// https://docs.slack.dev/messaging/formatting-message-text#date-formatting
func slackDate(t time.Time) string {
	return fmt.Sprintf("<!date^%d^{date_short_pretty} {time}|%s>", t.Unix(), t.UTC().Format(time.RFC3339))
}

// summary is the notification text: [Priority] rule on hostname.
func summary(evt *event.Event) string {
	s := "[" + evt.Priority.String() + "] " + evt.Rule
	if evt.Hostname != "" {
		s += " on " + evt.Hostname
	}
	return s
}

func (d *driver) fields(evt *event.Event) []textObject {
	fields := []textObject{
		mrkdwn(fieldText("rule", evt.Rule)),
		mrkdwn(fieldText("priority", evt.Priority.String())),
		mrkdwn(fieldText("source", evt.Source)),
	}
	if evt.Hostname != "" {
		fields = append(fields, mrkdwn(fieldText("hostname", evt.Hostname)))
	}
	if tags := shared.FormatTags(evt.Tags, ", "); tags != "" {
		fields = append(fields, mrkdwn(fieldText("tags", tags)))
	}
	fields = append(fields, mrkdwn("*time*\n"+slackDate(evt.Time)))
	keys := shared.SortMapKeys(evt.OutputFields)
	for i, k := range keys {
		if len(fields) >= maxFields {
			d.logger.Warn("field limit reached, remaining output fields dropped",
				"limit", maxFields, "dropped", len(keys)-i)
			break
		}
		fields = append(fields, mrkdwn(fieldText(k, fmt.Sprintf("%v", evt.OutputFields[k]))))
	}
	return fields
}

func (d *driver) buildPayload(evt *event.Event) slackPayload {
	format := d.cfg.OutputFormat
	blocks := []block{{Type: "header", Text: &textObject{Type: "plain_text", Text: shared.TruncateRunes(evt.Rule, maxHeaderRunes)}}}
	if (format == formatAll || format == formatText) && evt.Output != "" {
		text := mrkdwn(escapeMrkdwn(evt.Output, maxSectionRunes))
		blocks = append(blocks, block{Type: "section", Text: &text})
	}
	if format == formatAll || format == formatFields {
		fields := d.fields(evt)
		for len(fields) > 0 {
			n := min(len(fields), maxFieldsPerSection)
			blocks = append(blocks, block{Type: "section", Fields: fields[:n]})
			fields = fields[n:]
		}
	}
	if d.cfg.Footer != "" {
		blocks = append(blocks, block{Type: "context", Elements: []textObject{mrkdwn(shared.TruncateRunes(d.cfg.Footer, maxFooterRunes))}})
	}

	text := escapeMrkdwn(summary(evt), maxSectionRunes)
	if d.messageTmpl != nil {
		var buf bytes.Buffer
		if err := d.messageTmpl.Execute(&buf, evt); err != nil {
			d.logger.Warn("message template execution failed", "error", shared.WrapDeliveryError(name, shared.OpRenderMessage, err))
		} else if rendered := strings.TrimSpace(buf.String()); rendered != "" {
			text = shared.TruncateRunes(rendered, maxSectionRunes)
		}
	}

	return slackPayload{
		Text: text,
		Attachments: []slackAttachment{{
			Color:    shared.PriorityColor(evt.Priority),
			Fallback: text,
			Blocks:   blocks,
		}},
	}
}
