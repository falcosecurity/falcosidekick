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
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const testEndpoint = "/services/T000/B000/XXXX"

func runSlackCases(t *testing.T, cases []testutil.OutputTestCase) {
	t.Helper()
	for i := range cases {
		config := map[string]any{"secret_endpoint": testEndpoint}
		maps.Copy(config, cases[i].Config)
		cases[i].Config = config
	}
	testutil.RunOutputTests(t, &OutputType, cases)
}

func TestSlackCommonCases(t *testing.T) {
	runSlackCases(t, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "host"},
		{Name: "returns error on server 500", AddressField: "host", MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestSlackPayloadFormat(t *testing.T) {
	runSlackCases(t, []testutil.OutputTestCase{
		{
			Name:         "sends attachment with priority color",
			AddressField: "host",
			ValidateReq: func(t *testing.T, req *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				require.Len(t, payload.Attachments, 1)
				assert.NotEmpty(t, payload.Attachments[0].Color)
				assert.NotEmpty(t, payload.Attachments[0].Fields)
			},
		},
		{
			Name:         "includes channel when configured",
			AddressField: "host",
			Config:       map[string]any{"channel": "#alerts"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				assert.Equal(t, "#alerts", payload.Channel)
			},
		},
		{
			Name:         "includes username and icon",
			AddressField: "host",
			Config:       map[string]any{"bot_username": "FalcoBot", "icon_url": "https://example.com/icon.png"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				assert.Equal(t, "FalcoBot", payload.Username)
				assert.Equal(t, "https://example.com/icon.png", payload.IconURL)
			},
		},
		{
			Name:         "text-only format omits fields",
			AddressField: "host",
			Config:       map[string]any{"output_format": "text"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				require.Len(t, payload.Attachments, 1)
				assert.Empty(t, payload.Attachments[0].Fields)
				assert.NotEmpty(t, payload.Attachments[0].Text)
			},
		},
	})
}

func TestSlackCreateValidation(t *testing.T) {
	_, err := createOutput(map[string]any{}, output.Deps{})
	assert.Error(t, err, "missing secret_endpoint must fail")
}

func TestSlackMessageTemplate(t *testing.T) {
	runSlackCases(t, []testutil.OutputTestCase{
		{
			Name:         "renders message template",
			AddressField: "host",
			Config:       map[string]any{"message_format": "Alert: {{ .Rule }}"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				assert.Contains(t, payload.Text, "Alert:")
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

func TestBuildPayloadMrkdwnIn(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatText, Footer: defaultFooter}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()

	payload := o.buildPayload(evt)
	require.Len(t, payload.Attachments, 1)
	assert.Contains(t, payload.Attachments[0].MrkdwnIn, "text")
	assert.Contains(t, payload.Attachments[0].MrkdwnIn, "fallback")
}

func TestBuildPayloadIconEmoji(t *testing.T) {
	o := &driver{cfg: config{
		OutputFormat: formatText,
		Footer:       defaultFooter,
		IconEmoji:    ":ghost:",
	}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()

	payload := o.buildPayload(evt)
	assert.Equal(t, ":ghost:", payload.IconEmoji)
}

func TestBuildPayloadFieldsOnlyFormat(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatFields, Footer: defaultFooter}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()

	payload := o.buildPayload(evt)
	require.Len(t, payload.Attachments, 1)

	att := payload.Attachments[0]
	assert.NotEmpty(t, att.Fields, "fields format must include fields")
	assert.Empty(t, att.Text, "fields format must not include text body")
}

func TestBuildPayloadAllFormat(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()

	payload := o.buildPayload(evt)
	att := payload.Attachments[0]
	assert.NotEmpty(t, att.Fields, "all format must include fields")
	assert.NotEmpty(t, att.Text, "all format must include text body")
}

func TestBuildPayloadEveryPriorityHasColor(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatText, Footer: defaultFooter}, logger: slog.Default()}

	priorities := []event.Priority{
		event.PriorityDebug, event.PriorityInformational, event.PriorityNotice,
		event.PriorityWarning, event.PriorityError, event.PriorityCritical,
		event.PriorityAlert, event.PriorityEmergency,
	}
	for _, p := range priorities {
		t.Run(string(p), func(t *testing.T) {
			evt := testutil.CreateValidEvent()
			evt.Priority = p
			payload := o.buildPayload(evt)
			color := payload.Attachments[0].Color
			assert.NotEmpty(t, color, "priority %s must produce a color", p)
			assert.Equal(t, shared.PriorityColor(p), color, "must use shared PriorityColor")
		})
	}
}

func TestBuildPayloadNoHostname(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()
	evt.Hostname = ""

	payload := o.buildPayload(evt)
	for _, f := range payload.Attachments[0].Fields {
		assert.NotEqual(t, "hostname", f.Title, "empty hostname must not produce a field")
	}
}

func TestBuildPayloadNoTags(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()
	evt.Tags = nil

	payload := o.buildPayload(evt)
	for _, f := range payload.Attachments[0].Fields {
		assert.NotEqual(t, "tags", f.Title, "nil tags must not produce a field")
	}
}

func TestBuildPayloadTagsSorted(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()
	evt.Tags = []string{"z", "a", "m"}

	payload := o.buildPayload(evt)
	var tagsField slackAttachmentField
	for _, f := range payload.Attachments[0].Fields {
		if f.Title == "tags" {
			tagsField = f
			break
		}
	}
	assert.Equal(t, "a, m, z", tagsField.Value)
}

func TestBuildPayloadOutputFieldsOrder(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()
	evt.OutputFields = map[string]interface{}{
		"z.field": "zz",
		"a.field": "aa",
	}

	payload := o.buildPayload(evt)
	var fieldTitles []string
	for _, f := range payload.Attachments[0].Fields {
		if f.Title == "a.field" || f.Title == "z.field" {
			fieldTitles = append(fieldTitles, f.Title)
		}
	}
	require.Len(t, fieldTitles, 2)
	assert.Equal(t, "a.field", fieldTitles[0])
	assert.Equal(t, "z.field", fieldTitles[1])
}

func TestBuildPayloadMessageTemplateExec(t *testing.T) {
	tmpl, err := template.New("slack").Parse("Rule: {{ .Rule }}")
	require.NoError(t, err)

	o := &driver{
		cfg:         config{OutputFormat: formatText, Footer: defaultFooter},
		messageTmpl: tmpl,
		logger:      slog.Default(),
	}
	evt := testutil.CreateValidEvent()
	payload := o.buildPayload(evt)
	assert.Equal(t, "Rule: Write below binary dir", payload.Text)
}

func TestBuildPayloadMessageTemplateBadField(t *testing.T) {
	tmpl, err := template.New("slack").Parse("{{ .NonExistent }}")
	require.NoError(t, err)

	o := &driver{
		cfg:         config{OutputFormat: formatText, Footer: defaultFooter},
		messageTmpl: tmpl,
		logger:      slog.Default(),
	}
	evt := testutil.CreateValidEvent()
	payload := o.buildPayload(evt)
	assert.Empty(t, payload.Text, "failed template must produce empty text")
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
				"host":            server.URL,
				"secret_endpoint": testEndpoint,
				"message_format":  `{{index "private-template-token" -1}}`,
			}, output.Deps{Logger: slog.New(handler)})
			require.NoError(t, err)
			evt := testutil.CreateValidEvent()
			require.NoError(t, driver.Send(t.Context(), evt))
			var payload slackPayload
			require.NoError(t, json.Unmarshal(<-requests, &payload))
			assert.Empty(t, payload.Text)
			require.Len(t, payload.Attachments, 1)
			assert.Equal(t, evt.Output, payload.Attachments[0].Text)
			assert.Contains(t, logs.String(), "cannot render message template")
			assert.NotContains(t, logs.String(), "private-template-token")
		})
	}
}

func TestBuildPayloadChannel(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatText, Footer: defaultFooter, Channel: "#security"}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()
	payload := o.buildPayload(evt)
	assert.Equal(t, "#security", payload.Channel)
}

func TestBuildPayloadNoChannel(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatText, Footer: defaultFooter}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()
	payload := o.buildPayload(evt)
	assert.Empty(t, payload.Channel)
}

func TestCreateOutputInvalidTemplate(t *testing.T) {
	_, err := createOutput(map[string]any{
		"secret_endpoint": testEndpoint,
		"message_format":  "{{ .Broken",
	}, output.Deps{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Go template")
}

func TestCreateRuntimeDefaults(t *testing.T) {
	d, err := createOutput(map[string]any{
		"secret_endpoint": testEndpoint,
	}, output.Deps{})
	require.NoError(t, err)

	o, ok := d.(*driver)
	require.True(t, ok)
	assert.Equal(t, formatAll, o.cfg.OutputFormat)
	assert.Equal(t, defaultFooter, o.cfg.Footer)
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

func TestBuildPayloadFieldShortDetection(t *testing.T) {
	o := &driver{cfg: config{OutputFormat: formatAll, Footer: defaultFooter}, logger: slog.Default()}
	evt := testutil.CreateValidEvent()
	evt.OutputFields = map[string]interface{}{
		"short": "x",
		"long":  "this is a long value that exceeds thirty six runes easily",
	}

	payload := o.buildPayload(evt)
	for _, f := range payload.Attachments[0].Fields {
		if f.Title == "short" {
			assert.True(t, f.Short)
		}
		if f.Title == "long" {
			assert.False(t, f.Short)
		}
	}
}

func TestSlackFieldsFormat(t *testing.T) {
	runSlackCases(t, []testutil.OutputTestCase{
		{
			Name:         "fields format sends fields without text",
			AddressField: "host",
			Config:       map[string]any{"output_format": "fields"},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				var payload slackPayload
				require.NoError(t, json.Unmarshal(body, &payload))
				require.Len(t, payload.Attachments, 1)
				assert.NotEmpty(t, payload.Attachments[0].Fields)
				assert.Empty(t, payload.Attachments[0].Text)
			},
		},
	})
}

func TestSlackBotUsernameIsNotBasicAuth(t *testing.T) {
	var authorization []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Values("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	d, err := createOutput(map[string]any{
		"host": server.URL, "secret_endpoint": testEndpoint, "bot_username": "FalcoBot",
	}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Empty(t, authorization)

	names := map[string]int{}
	for _, field := range OutputType.Schema.Fields {
		names[field.Name]++
	}
	for name, count := range names {
		assert.Equal(t, 1, count, name)
	}
}
