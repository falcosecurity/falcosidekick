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

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// Slack API limits (from https://api.slack.com/reference/surfaces/formatting).
const (
	maxTitleRunes      = 1024
	maxFooterRunes     = 300
	maxFieldsPerAttach = 100
)

type slackPayload struct {
	Text        string            `json:"text,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconURL     string            `json:"icon_url,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Fallback string                 `json:"fallback"`
	Color    string                 `json:"color"`
	Text     string                 `json:"text,omitempty"`
	Footer   string                 `json:"footer,omitempty"`
	MrkdwnIn []string               `json:"mrkdwn_in,omitempty"`
	Fields   []slackAttachmentField `json:"fields"`
}

type slackAttachmentField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func (d *driver) buildPayload(evt *event.Event) slackPayload {
	var fields []slackAttachmentField
	format := d.cfg.OutputFormat

	if format == formatAll || format == formatFields {
		fields = append(fields,
			slackAttachmentField{Title: "rule", Value: shared.TruncateRunes(evt.Rule, maxTitleRunes), Short: true},
			slackAttachmentField{Title: "priority", Value: string(evt.Priority), Short: true},
			slackAttachmentField{Title: "source", Value: evt.Source, Short: true},
		)
		if evt.Hostname != "" {
			fields = append(fields, slackAttachmentField{Title: "hostname", Value: evt.Hostname, Short: true})
		}
		if tags := shared.FormatTags(evt.Tags, ", "); tags != "" {
			fields = append(fields, slackAttachmentField{Title: "tags", Value: tags, Short: true})
		}
		for _, k := range shared.SortMapKeys(evt.OutputFields) {
			if len(fields) >= maxFieldsPerAttach {
				d.logger.Warn("attachment field limit reached, remaining fields dropped",
					"limit", maxFieldsPerAttach, "total_fields", len(evt.OutputFields))
				break
			}
			v := fmt.Sprintf("%v", evt.OutputFields[k])
			fields = append(fields, slackAttachmentField{
				Title: k,
				Value: v,
				Short: len([]rune(v)) < 36,
			})
		}
		fields = append(fields, slackAttachmentField{Title: "time", Value: evt.Time.String()})
	}

	attachment := slackAttachment{
		Fallback: shared.TruncateRunes(evt.Output, maxTitleRunes),
		Fields:   fields,
		Footer:   shared.TruncateRunes(d.cfg.Footer, maxFooterRunes),
		Color:    shared.PriorityColor(evt.Priority),
		MrkdwnIn: []string{"fallback", "text"},
	}

	if format == formatAll || format == formatText {
		attachment.Text = evt.Output
	}

	var messageText string
	if d.messageTmpl != nil {
		var buf bytes.Buffer
		if err := d.messageTmpl.Execute(&buf, evt); err == nil {
			messageText = buf.String()
		} else {
			d.logger.Warn("message template execution failed", "error", shared.WrapDeliveryError("slack", "render message", err))
		}
	}

	p := slackPayload{
		Text:        messageText,
		Username:    d.cfg.BotUsername,
		IconURL:     d.cfg.IconURL,
		IconEmoji:   d.cfg.IconEmoji,
		Attachments: []slackAttachment{attachment},
	}
	if d.cfg.Channel != "" {
		p.Channel = d.cfg.Channel
	}
	return p
}
