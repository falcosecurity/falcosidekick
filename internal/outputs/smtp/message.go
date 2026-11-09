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

package smtp

import (
	"fmt"
	htmltemplate "html/template"
	texttemplate "text/template"
	"time"

	mail "github.com/wneessen/go-mail"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// maxSubjectRunes keeps the encoded Subject header within the RFC 5322 line limit.
const maxSubjectRunes = 200

var (
	textTemplate = texttemplate.Must(texttemplate.New("text").Parse(textBody))
	htmlTemplate = htmltemplate.Must(htmltemplate.New("html").Parse(htmlBody))
)

// templateData is the view of an event that the templates render.
type templateData struct {
	Priority string
	Color    string
	Output   string
	Rule     string
	Source   string
	Hostname string
	Time     string
	Tags     string
	Fields   []field
}

type field struct {
	Name  string
	Value string
}

func newTemplateData(evt *event.Event) templateData {
	keys := shared.SortMapKeys(evt.OutputFields)
	fields := make([]field, 0, len(keys))
	for _, key := range keys {
		fields = append(fields, field{Name: key, Value: fmt.Sprint(evt.OutputFields[key])})
	}
	return templateData{
		Priority: evt.Priority.String(),
		Color:    shared.PriorityColor(evt.Priority),
		Output:   evt.Output,
		Rule:     evt.Rule,
		Source:   evt.Source,
		Hostname: evt.Hostname,
		Time:     evt.Time.UTC().Format(time.RFC3339Nano),
		Tags:     shared.FormatTags(evt.Tags, ", "),
		Fields:   fields,
	}
}

// subject is "[Priority] rule on hostname": both are stable per alert, unlike the output text.
func subject(evt *event.Event) string {
	s := "[" + evt.Priority.String() + "] " + evt.Rule
	if evt.Hostname != "" {
		s += " on " + evt.Hostname
	}
	return shared.TruncateRunes(s, maxSubjectRunes)
}

// message builds a text body, plus an HTML alternative in html format.
func (d *driver) message(evt *event.Event) (*mail.Msg, error) {
	data := newTemplateData(evt)
	msg := mail.NewMsg()
	msg.SetAddrHeaderFromMailAddress(mail.HeaderFrom, d.from)
	msg.SetAddrHeaderFromMailAddress(mail.HeaderTo, d.to...)
	msg.Subject(subject(evt))
	msg.SetDateWithValue(evt.Time)
	msg.SetMessageID()
	// RFC 3834: automatic responders do not answer this message.
	msg.SetGenHeader("Auto-Submitted", "auto-generated")
	if err := msg.SetBodyTextTemplate(textTemplate, data); err != nil {
		return nil, err
	}
	if d.cfg.Format == formatHTML {
		if err := msg.AddAlternativeHTMLTemplate(htmlTemplate, data); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

const textBody = `{{ .Priority }}: {{ .Output }}

Rule:     {{ .Rule }}
Priority: {{ .Priority }}
Source:   {{ .Source }}
{{- if .Hostname }}
Hostname: {{ .Hostname }}
{{- end }}
Time:     {{ .Time }}
{{- if .Tags }}
Tags:     {{ .Tags }}
{{- end }}
{{ if .Fields }}
Output fields:
{{- range .Fields }}
  {{ .Name }}: {{ .Value }}
{{- end }}
{{ end -}}
`

const htmlBody = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ .Priority }}: {{ .Rule }}</title>
</head>
<body style="margin:0; padding:16px; background-color:#f4f5f7; font-family:Arial, Helvetica, sans-serif; color:#1f2328;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:720px; margin:0 auto; background-color:#ffffff; border-collapse:collapse;">
<tr><td style="border-top:6px solid {{ .Color }}; padding:16px 20px;">
<p style="margin:0 0 4px; font-size:12px; font-weight:bold; text-transform:uppercase; color:#57606a;">{{ .Priority }}</p>
<h1 style="margin:0 0 12px; font-size:18px; line-height:1.4;">{{ .Rule }}</h1>
<p style="margin:0; font-size:14px; line-height:1.5; word-break:break-word;">{{ .Output }}</p>
</td></tr>
<tr><td style="padding:0 20px 16px;">
<table role="presentation" width="100%" cellpadding="6" cellspacing="0" style="border-collapse:collapse; font-size:13px;">
<tr><th align="left" style="width:30%; border-bottom:1px solid #d0d7de; color:#57606a;">Source</th><td style="border-bottom:1px solid #d0d7de;">{{ .Source }}</td></tr>
{{- if .Hostname }}
<tr><th align="left" style="border-bottom:1px solid #d0d7de; color:#57606a;">Hostname</th><td style="border-bottom:1px solid #d0d7de;">{{ .Hostname }}</td></tr>
{{- end }}
<tr><th align="left" style="border-bottom:1px solid #d0d7de; color:#57606a;">Time</th><td style="border-bottom:1px solid #d0d7de;">{{ .Time }}</td></tr>
{{- if .Tags }}
<tr><th align="left" style="border-bottom:1px solid #d0d7de; color:#57606a;">Tags</th><td style="border-bottom:1px solid #d0d7de;">{{ .Tags }}</td></tr>
{{- end }}
</table>
</td></tr>
{{- if .Fields }}
<tr><td style="padding:0 20px 20px;">
<h2 style="margin:0 0 8px; font-size:14px;">Output fields</h2>
<table role="presentation" width="100%" cellpadding="6" cellspacing="0" style="border-collapse:collapse; font-size:13px; font-family:Menlo, Consolas, monospace;">
{{- range .Fields }}
<tr><th align="left" style="width:30%; border-bottom:1px solid #d0d7de; color:#57606a; font-weight:normal;">{{ .Name }}</th><td style="border-bottom:1px solid #d0d7de; word-break:break-all;">{{ .Value }}</td></tr>
{{- end }}
</table>
</td></tr>
{{- end }}
</table>
</body>
</html>
`
