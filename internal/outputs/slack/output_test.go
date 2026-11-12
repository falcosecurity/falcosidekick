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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	testEndpoint = "/services/T000/B000/XXXX"
	// testDate is testutil.CreateValidEvent's time, 2026-04-01T10:30:00Z.
	testDate = "<!date^1775039400^{date_short_pretty} {time}|2026-04-01T10:30:00Z>"
)

func runSlackCases(t *testing.T, cases []testutil.OutputTestCase) {
	t.Helper()
	for i := range cases {
		config := map[string]any{"secret_endpoint": testEndpoint}
		maps.Copy(config, cases[i].Config)
		cases[i].Config = config
	}
	testutil.RunOutputTests(t, &OutputType, cases)
}

func newDriver(cfg *config) *driver {
	if cfg.OutputFormat == "" {
		cfg.OutputFormat = formatAll
	}
	return &driver{cfg: *cfg, logger: slog.New(slog.DiscardHandler)}
}

// sectionFields returns the texts of every section field, in order.
func sectionFields(p slackPayload) []string {
	var out []string
	for _, b := range p.Attachments[0].Blocks {
		for _, f := range b.Fields {
			out = append(out, f.Text)
		}
	}
	return out
}

func blockTypes(p slackPayload) []string {
	out := make([]string, 0, len(p.Attachments[0].Blocks))
	for _, b := range p.Attachments[0].Blocks {
		kind := b.Type
		if b.Type == "section" && b.Fields != nil {
			kind = "section/fields"
		}
		out = append(out, kind)
	}
	return out
}

func TestSlackCommonCases(t *testing.T) {
	runSlackCases(t, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "host"},
		{Name: "returns error on server 500", AddressField: "host", MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestSlackCreateValidation(t *testing.T) {
	_, err := createOutput(map[string]any{}, output.Deps{})
	assert.Error(t, err, "missing secret_endpoint must fail")
}

// The sender overrides, which Slack-app webhooks ignore, and message_format are refused.
func TestSlackRemovedKeysAreRefused(t *testing.T) {
	for key, value := range map[string]any{
		"channel": "#alerts", "bot_username": "FalcoBot", "icon_url": shared.FalcosidekickIconURL,
		"icon_emoji": ":ghost:", "message_format": "{{ .Rule }}",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := createOutput(map[string]any{"secret_endpoint": testEndpoint, key: value}, output.Deps{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
	}
}

func TestBuildPayloadAll(t *testing.T) {
	d := newDriver(&config{Footer: suggestedFooter})
	evt := testutil.CreateValidEvent()
	p := d.buildPayload(evt)

	body, err := json.Marshal(p)
	require.NoError(t, err)
	for _, key := range []string{"channel", "username", "icon_url", "icon_emoji", `"fields":[{"title"`} {
		assert.NotContains(t, string(body), key)
	}

	assert.Equal(t, "[Error] Write below binary dir on node-1", p.Text)
	require.Len(t, p.Attachments, 1)
	att := p.Attachments[0]
	assert.Equal(t, shared.PriorityColor(event.PriorityError), att.Color)
	assert.Equal(t, p.Text, att.Fallback)
	assert.Equal(t, []string{"header", "section", "section/fields", "context"}, blockTypes(p))
	assert.Equal(t, &textObject{Type: "plain_text", Text: "Write below binary dir"}, att.Blocks[0].Text)
	assert.Equal(t, &textObject{Type: "mrkdwn", Text: evt.Output}, att.Blocks[1].Text)
	assert.Equal(t, []string{
		"*rule*\nWrite below binary dir",
		"*priority*\nError",
		"*source*\nsyscall",
		"*hostname*\nnode-1",
		"*tags*\nfilesystem, mitre_persistence",
		"*time*\n" + testDate,
		"*fd.name*\n/bin/hack",
		"*proc.cmdline*\ntouch /bin/hack",
		"*user.name*\nroot",
	}, sectionFields(p))
	for _, f := range att.Blocks[2].Fields {
		assert.Equal(t, "mrkdwn", f.Type)
	}
	assert.Equal(t, []textObject{{Type: "mrkdwn", Text: suggestedFooter}}, att.Blocks[3].Elements)
}

func TestBuildPayloadFormats(t *testing.T) {
	for _, tc := range []struct {
		format string
		want   []string
	}{
		{format: formatAll, want: []string{"header", "section", "section/fields"}},
		{format: formatText, want: []string{"header", "section"}},
		{format: formatFields, want: []string{"header", "section/fields"}},
	} {
		t.Run(tc.format, func(t *testing.T) {
			p := newDriver(&config{OutputFormat: tc.format}).buildPayload(testutil.CreateValidEvent())
			assert.Equal(t, tc.want, blockTypes(p), "no footer block unless set")
			assert.NotEmpty(t, p.Text, "notifications always have a text")
		})
	}
}

func TestBuildPayloadOptionalParts(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Hostname = ""
	evt.Tags = nil
	evt.Output = ""
	evt.OutputFields = nil
	p := newDriver(&config{}).buildPayload(evt)
	assert.Equal(t, "[Error] Write below binary dir", p.Text, "no hostname, no \"on\"")
	assert.Equal(t, []string{"header", "section/fields"}, blockTypes(p), "an empty output sends no empty section")
	assert.Equal(t, []string{"*rule*\nWrite below binary dir", "*priority*\nError", "*source*\nsyscall", "*time*\n" + testDate}, sectionFields(p))
}

func TestBuildPayloadEveryPriorityUsesThePalette(t *testing.T) {
	d := newDriver(&config{OutputFormat: formatText})
	for _, p := range []event.Priority{
		event.PriorityDebug, event.PriorityInformational, event.PriorityNotice, event.PriorityWarning,
		event.PriorityError, event.PriorityCritical, event.PriorityAlert, event.PriorityEmergency,
	} {
		t.Run(string(p), func(t *testing.T) {
			evt := testutil.CreateValidEvent()
			evt.Priority = p
			assert.Equal(t, shared.PriorityColor(p), d.buildPayload(evt).Attachments[0].Color)
		})
	}
}

func TestSlackDate(t *testing.T) {
	evt := testutil.CreateValidEvent()
	assert.Equal(t, testDate, slackDate(evt.Time))
	assert.Equal(t, testDate, slackDate(evt.Time.In(time.FixedZone("UTC+9", 9*3600))), "the fallback is UTC")
}

func TestBuildPayloadEscapesEventText(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Rule = "R <!channel>"
	evt.Hostname = "h&<x>"
	evt.Output = "out <!here> & <https://evil.example|click>"
	evt.OutputFields = map[string]any{"a<b": "<@U123>"}
	p := newDriver(&config{}).buildPayload(evt)
	assert.Equal(t, "[Error] R &lt;!channel&gt; on h&amp;&lt;x&gt;", p.Text)
	assert.Equal(t, "R <!channel>", p.Attachments[0].Blocks[0].Text.Text, "plain_text needs no escaping")
	assert.Equal(t, "out &lt;!here&gt; &amp; &lt;https://evil.example|click&gt;", p.Attachments[0].Blocks[1].Text.Text)
	assert.Contains(t, sectionFields(p), "*a&lt;b*\n&lt;@U123&gt;")
}

func TestEscapeMrkdwnCut(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		max  int
	}{
		{in: "abc", max: 3, want: "abc"},
		{in: "a&b", max: 7, want: "a&amp;b"},
		{in: "abcdef", max: 5, want: "ab..."},
		{in: "a&bcdef", max: 9, want: "a&amp;..."},
		{in: "ab&cdef", max: 8, want: "ab..."}, // the escape sequence is not split
	} {
		t.Run(tc.in, func(t *testing.T) {
			got := escapeMrkdwn(tc.in, tc.max)
			assert.Equal(t, tc.want, got)
			assert.LessOrEqual(t, utf8.RuneCountInString(got), tc.max)
		})
	}
}

func TestBuildPayloadLimits(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Rule = strings.Repeat("r", 500)
	evt.Output = strings.Repeat("o", 5000)
	evt.OutputFields = map[string]any{}
	for i := range 150 {
		evt.OutputFields[fmt.Sprintf("f%03d", i)] = strings.Repeat("v", 3000)
	}
	p := newDriver(&config{Footer: strings.Repeat("f", 500)}).buildPayload(evt)
	blocks := p.Attachments[0].Blocks
	// Block Kit limits: header 150, section text 3000, field 2000, 10 fields per section, 50 blocks.
	assert.Equal(t, 150, utf8.RuneCountInString(blocks[0].Text.Text))
	assert.Equal(t, 3000, utf8.RuneCountInString(blocks[1].Text.Text), "the cut keeps the whole budget")
	assert.LessOrEqual(t, len(blocks), 50, "Slack accepts at most 50 blocks")
	assert.Equal(t, 300, utf8.RuneCountInString(blocks[len(blocks)-1].Elements[0].Text))
	fields := sectionFields(p)
	assert.Len(t, fields, 100)
	for _, b := range blocks {
		assert.LessOrEqual(t, len(b.Fields), 10, "Slack accepts at most 10 fields per section")
	}
	assert.Len(t, blocks, 1+1+10+1, "header, text, 100 fields in 10 sections, footer")
	for _, f := range fields[6:] {
		assert.Equal(t, 2000, utf8.RuneCountInString(f), "a long output field is cut to the field limit")
	}
	assert.Equal(t, "*time*\n"+testDate, fields[5], "time is kept when output fields are dropped")
}

func TestBuildPayloadMessageTemplate(t *testing.T) {
	for _, tc := range []struct {
		name string
		tmpl string
		want string
	}{
		{name: "rendered", tmpl: "Rule: {{ .Rule }}", want: "Rule: Write below binary dir"},
		{name: "execution fails", tmpl: "{{ .NonExistent }}", want: "[Error] Write below binary dir on node-1"},
		{name: "renders empty", tmpl: "{{ if false }}x{{ end }}", want: "[Error] Write below binary dir on node-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDriver(&config{OutputFormat: formatText})
			d.messageTmpl = template.Must(template.New(name).Parse(tc.tmpl))
			p := d.buildPayload(testutil.CreateValidEvent())
			assert.Equal(t, tc.want, p.Text)
			assert.Equal(t, tc.want, p.Attachments[0].Fallback)
		})
	}
}

func TestSlackMessageTemplateIsSent(t *testing.T) {
	runSlackCases(t, []testutil.OutputTestCase{
		{
			Name:         "renders message template",
			AddressField: "host",
			Config:       map[string]any{"message_template": "Alert: {{ .Rule }}"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				assert.Equal(t, "Alert: Write below binary dir", payload.Text)
			},
		},
	})
}

func TestCheckSlackResponse(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{"ok response", []byte("ok"), false},
		{"ok with newline", []byte("ok\n"), false},
		{"empty body", []byte{}, false},
		{"invalid_payload", []byte("invalid_payload"), true},
		{"channel_not_found", []byte("channel_not_found"), true},
		{"no_service", []byte("no_service"), true},
		{"no_text", []byte("no_text"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSlackResponse(tt.body)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "slack response:")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSlackProtocolDiagnosticCodes(t *testing.T) {
	codes := []string{
		"action_prohibited", "channel_is_archived", "channel_not_found", "invalid_payload",
		"invalid_token", "no_active_hooks", "no_service", "no_service_id", "no_team", "no_text",
		"posting_to_general_channel_denied", "rollup_error", "team_disabled", "too_many_attachments", "user_not_found",
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			err := checkSlackResponse([]byte("\n" + code + "\n"))
			require.EqualError(t, err, "slack response: "+code)
			var diagnostic *shared.DeliveryError
			assert.ErrorAs(t, err, &diagnostic)
		})
	}
}

func TestSlackSendSafeDiagnostics(t *testing.T) {
	const secret = "SLACK_RESPONSE_SECRET"
	for _, tc := range []struct {
		name   string
		body   string
		want   string
		status int
	}{
		{name: "known rejection", body: "invalid_token", want: "invalid_token", status: http.StatusOK},
		{name: "reflected credential", body: secret, want: "unexpected response", status: http.StatusOK},
		{name: "code with untrusted suffix", body: "invalid_token: " + secret, want: "unexpected response", status: http.StatusOK},
		{name: "HTTP rejection", body: secret, want: "HTTP 401 Unauthorized", status: http.StatusUnauthorized},
		{name: "archived channel", body: "channel_is_archived", want: "HTTP 410 Gone: channel_is_archived", status: http.StatusGone},
		{name: "invalid HTTP payload", body: "invalid_payload", want: "HTTP 400 Bad Request: invalid_payload", status: http.StatusBadRequest},
		{name: "prohibited action", body: "action_prohibited", want: "HTTP 403 Forbidden: action_prohibited", status: http.StatusForbidden},
		{name: "non-2xx with ok body still fails", body: "ok", want: "HTTP 400 Bad Request", status: http.StatusBadRequest},
		{name: "non-2xx with empty body still fails", want: "HTTP 500 Internal Server Error", status: http.StatusInternalServerError},
		{name: "empty success unchanged", status: http.StatusOK},
		{name: "ok success unchanged", body: "ok\n", status: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)
			d, err := createOutput(map[string]any{
				"host":            server.URL,
				"secret_endpoint": "/services/PATH_SECRET",
				"query_params":    map[string]any{"token": map[string]any{"secrets": []string{"QUERY_SECRET"}}},
			}, output.Deps{})
			require.NoError(t, err)

			err = d.Send(context.Background(), testutil.CreateValidEvent())
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), secret)
			assert.NotContains(t, err.Error(), "PATH_SECRET")
			assert.NotContains(t, err.Error(), "QUERY_SECRET")
			var diagnostic *shared.DeliveryError
			assert.ErrorAs(t, err, &diagnostic)
		})
	}
}

func TestSlackTemplateSafeDiagnostic(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			var logs bytes.Buffer
			var handler slog.Handler = slog.NewTextHandler(&logs, nil)
			if format == "json" {
				handler = slog.NewJSONHandler(&logs, nil)
			}
			requests := make(chan []byte, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				requests <- body
				_, err = io.WriteString(w, "ok")
				assert.NoError(t, err)
			}))
			defer server.Close()
			driver, err := createOutput(map[string]any{
				"host":             server.URL,
				"secret_endpoint":  testEndpoint,
				"message_template": `{{index "private-template-token" -1}}`,
			}, output.Deps{Logger: slog.New(handler)})
			require.NoError(t, err)
			evt := testutil.CreateValidEvent()
			require.NoError(t, driver.Send(t.Context(), evt))
			var payload slackPayload
			require.NoError(t, json.Unmarshal(<-requests, &payload))
			assert.Equal(t, summary(evt), payload.Text)
			require.Len(t, payload.Attachments, 1)
			assert.Equal(t, evt.Output, payload.Attachments[0].Blocks[1].Text.Text)
			assert.Contains(t, logs.String(), "cannot render message template")
			assert.NotContains(t, logs.String(), "private-template-token")
		})
	}
}

func TestCreateOutputInvalidTemplate(t *testing.T) {
	_, err := createOutput(map[string]any{
		"secret_endpoint":  testEndpoint,
		"message_template": "{{ .Broken",
	}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message_template: invalid Go template")
}

func TestCreateOutputInvalidFormat(t *testing.T) {
	_, err := createOutput(map[string]any{"secret_endpoint": testEndpoint, "output_format": "blocks"}, output.Deps{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "output_format: must be all/fields/text")
}

func TestCreateRuntimeDefaults(t *testing.T) {
	d, err := createOutput(map[string]any{
		"secret_endpoint": testEndpoint,
	}, output.Deps{})
	require.NoError(t, err)

	o, ok := d.(*driver)
	require.True(t, ok)
	assert.Equal(t, formatAll, o.cfg.OutputFormat)
	assert.Empty(t, o.cfg.Footer, "the footer is only suggested")
	assert.NotContains(t, blockTypes(o.buildPayload(testutil.CreateValidEvent())), "context", "no footer unless set")
}

func TestSchema(t *testing.T) {
	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		_, dup := fields[f.Name]
		require.False(t, dup, f.Name)
		fields[f.Name] = f
	}
	for _, removed := range []string{"channel", "bot_username", "icon_url", "icon_emoji", "message_format"} {
		assert.NotContains(t, fields, removed)
	}
	assert.Contains(t, fields, "message_template")
	assert.Nil(t, fields["footer"].Default)
	assert.Equal(t, suggestedFooter, fields["footer"].Suggested)
	assert.Equal(t, formatAll, fields["output_format"].Default)
}

func TestSlackHealthCheckSendsNoRequest(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d, err := OutputType.New(map[string]any{"host": server.URL, "secret_endpoint": testEndpoint}, output.Deps{})
	require.NoError(t, err)
	assert.NoError(t, d.HealthCheck(context.Background()))
	server.Close()
	assert.Zero(t, calls, "a probe would post a message to the channel")
}

func TestSlackInit(t *testing.T) {
	o := &driver{}
	assert.NoError(t, o.Init(context.Background()))
}

func TestSlackClose(t *testing.T) {
	d, err := OutputType.New(map[string]any{"secret_endpoint": "/services/T/B/X"}, output.Deps{})
	require.NoError(t, err)
	assert.NoError(t, d.Close())
	assert.NoError(t, d.Close(), "Close is idempotent")
}

func TestSlackSendsBlocksInOneColoredAttachment(t *testing.T) {
	var authorization []string
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Values("Authorization")
		body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	d, err := createOutput(map[string]any{"host": server.URL, "secret_endpoint": testEndpoint}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Empty(t, authorization)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(body, &raw))
	keys := slices.Sorted(maps.Keys(raw))
	assert.Equal(t, []string{"attachments", "text"}, keys)
	var p slackPayload
	require.NoError(t, json.Unmarshal(body, &p))
	require.Len(t, p.Attachments, 1)
	assert.Equal(t, "header", p.Attachments[0].Blocks[0].Type)
}
