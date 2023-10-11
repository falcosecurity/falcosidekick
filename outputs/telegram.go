// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package outputs

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	textTemplate "text/template"

	"github.com/falcosecurity/falcosidekick/types"
)

func markdownV2EscapeText(text interface{}) string {

	replacer := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]", "(",
		"\\(", ")", "\\)", "~", "\\~", "`", "\\`", ">", "\\>",
		"#", "\\#", "+", "\\+", "-", "\\-", "=", "\\=", "|",
		"\\|", "{", "\\{", "}", "\\}", ".", "\\.", "!", "\\!",
	)

	return replacer.Replace(fmt.Sprintf("%v", text))
}

var (
	telegramMarkdownV2Tmpl = `*\[Falco\] \[{{markdownV2EscapeText .Priority }}\] {{markdownV2EscapeText .Rule }}*

• *Time*: {{markdownV2EscapeText .Time }}
• *Source*: {{markdownV2EscapeText .Source }}
• *Hostname*: {{markdownV2EscapeText .Hostname }}
• *Tags*: {{ range .Tags }}{{markdownV2EscapeText . }} {{ end }}
• *Fields*:
{{ range $key, $value := .OutputFields }}	  • *{{markdownV2EscapeText $key }}*: {{markdownV2EscapeText $value }}
{{ end }}

**Output**: {{markdownV2EscapeText .Output }}
`
)

// Payload
type telegramPayload struct {
	Text                  string `json:"text,omitempty"`
	ParseMode             string `json:"parse_mode,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview,omitempty"`
	ChatID                string `json:"chat_id,omitempty"`
}

func newTelegramPayload(falcopayload types.FalcoPayload, config *types.Configuration) telegramPayload {
	payload := telegramPayload{

		ParseMode:             "MarkdownV2",
		DisableWebPagePreview: true,
		ChatID:                config.Telegram.ChatID,
	}

	// template engine
	var textBuffer bytes.Buffer
	funcs := textTemplate.FuncMap{
		"markdownV2EscapeText": markdownV2EscapeText,
	}
	ttmpl, _ := textTemplate.New("telegram").Funcs(funcs).Parse(telegramMarkdownV2Tmpl)
	err := ttmpl.Execute(&textBuffer, falcopayload)
	if err != nil {
		log.Printf("[ERROR] : Telegram - %v\n", err)
		return payload
	}
	payload.Text = textBuffer.String()

	return payload
}

// TelegramPost posts event to Telegram
func (c *Client) TelegramPost(falcopayload types.FalcoPayload) {
	c.Stats.Telegram.Add(Total, 1)

	err := c.Post(newTelegramPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:telegram", "status:error"})
		c.Stats.Telegram.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "telegram", "status": Error}).Inc()
		log.Printf("[ERROR] : Telegram - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:telegram", "status:ok"})
	c.Stats.Telegram.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "telegram", "status": OK}).Inc()
}
