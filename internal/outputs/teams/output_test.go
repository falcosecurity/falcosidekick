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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const (
	testPath      = "/workflows/0123abcd/triggers/manual/paths/invoke"
	testSignature = "SIGNATURE_SECRET"
)

func baseConfig(host string) map[string]any {
	return map[string]any{
		"host":            host,
		"secret_endpoint": testPath,
		"query_params": map[string]any{
			"api-version": map[string]any{"values": []string{"2016-06-01"}},
			"sig":         map[string]any{"secrets": []string{testSignature}},
		},
	}
}

func newDriver(t *testing.T, cfg *config) *driver {
	t.Helper()
	cfg.Host = "https://h.example"
	cfg.SecretEndpoint = testPath
	require.Empty(t, cfg.validate())
	return &driver{cfg: *cfg, logger: slog.New(slog.DiscardHandler)}
}

func decodeCard(t *testing.T, body []byte) *adaptiveCard {
	t.Helper()
	var msg message
	require.NoError(t, json.Unmarshal(body, &msg))
	require.Equal(t, "message", msg.Type)
	require.Len(t, msg.Attachments, 1)
	assert.Nil(t, msg.Attachments[0].ContentURL)
	assert.Equal(t, adaptiveContentType, msg.Attachments[0].ContentType)
	return &msg.Attachments[0].Content
}

func findFacts(card *adaptiveCard) []fact {
	for i := range card.Body {
		if card.Body[i].Type == "FactSet" {
			return card.Body[i].Facts
		}
	}
	return nil
}

func findText(card *adaptiveCard) string {
	for i := 1; i < len(card.Body); i++ {
		if card.Body[i].Type == "TextBlock" {
			return card.Body[i].Text
		}
	}
	return ""
}

func TestValidation(t *testing.T) {
	tests := []struct {
		config map[string]any
		name   string
		want   string
	}{
		{name: "minimal", config: map[string]any{"host": "https://prod.logic.azure.com", "secret_endpoint": testPath}},
		{name: "missing host", config: map[string]any{"secret_endpoint": testPath}, want: "host: is required"},
		{name: "missing secret_endpoint", config: map[string]any{"host": "https://h.example"}, want: "secret_endpoint: is required"},
		{name: "public endpoint rejected", config: map[string]any{"host": "https://h.example", "secret_endpoint": testPath, "endpoint": "/x"}, want: "endpoint: is not supported"},
		{name: "unknown key", config: map[string]any{"host": "https://h.example", "secret_endpoint": testPath, "webhook_url": "x"}, want: "webhook_url"},
		{name: "fields format", config: map[string]any{"host": "https://h.example", "secret_endpoint": testPath, "output_format": "fields"}},
		{name: "text format", config: map[string]any{"host": "https://h.example", "secret_endpoint": testPath, "output_format": "text"}},
		{name: "v2 facts format renamed", config: map[string]any{"host": "https://h.example", "secret_endpoint": testPath, "output_format": "facts"}, want: "output_format: must be all/text/fields"},
		{name: "invalid image", config: map[string]any{"host": "https://h.example", "secret_endpoint": testPath, "activity_image": "file:///etc/x"}, want: "activity_image: must be an absolute http or https URL"},
		{name: "relative image", config: map[string]any{"host": "https://h.example", "secret_endpoint": testPath, "activity_image": "/img.png"}, want: "activity_image"},
		{
			name: "public signature rejected",
			config: map[string]any{"host": "https://h.example", "secret_endpoint": testPath, "query_params": map[string]any{
				"sig": map[string]any{"values": []string{testSignature}},
			}},
			want: `query_params["sig"]: is a credential; use secrets or files`,
		},
		{name: "invalid tls", config: map[string]any{"host": "https://h.example", "secret_endpoint": testPath, "tls": map[string]any{"ca_file": "/does/not/exist"}}, want: "tls"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := OutputType.New(tc.config, output.Deps{})
			if tc.want == "" {
				require.NoError(t, err)
				assert.Equal(t, name, d.Name())
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), testSignature)
			assert.NotContains(t, err.Error(), testPath)
		})
	}
}

func TestDefaults(t *testing.T) {
	d, err := OutputType.New(map[string]any{"host": "https://h.example", "secret_endpoint": testPath}, output.Deps{})
	require.NoError(t, err)
	o := d.(*driver)
	assert.Equal(t, formatAll, o.cfg.OutputFormat)
	assert.Equal(t, defaultActivityImage, o.cfg.ActivityImage)
	assert.Equal(t, output.RuntimeConfig{}, o.RuntimeConfig())
	assert.NoError(t, o.Init(context.Background()))
	assert.NoError(t, o.Close())
}

func TestSchema(t *testing.T) {
	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		_, dup := fields[f.Name]
		require.False(t, dup, f.Name)
		fields[f.Name] = f
	}
	assert.True(t, fields["secret_endpoint"].Secret)
	assert.True(t, fields["secret_endpoint"].Required)
	assert.True(t, fields["host"].Required)
	assert.Nil(t, fields["host"].Default)
	assert.NotContains(t, fields, "endpoint")
	assert.Equal(t, []string{"all", "text", "fields"}, fields["output_format"].Values)
	assert.Equal(t, defaultActivityImage, fields["activity_image"].Default)
	assert.Contains(t, fields, "runtime.minimum_priority")
	assert.True(t, fields["bearer_token"].Secret)
	assert.Equal(t, "chat", OutputType.Category)
}

func TestPayloadAllFormat(t *testing.T) {
	d := newDriver(t, &config{})
	evt := testutil.CreateValidEvent()
	body, err := d.buildPayload(evt)
	require.NoError(t, err)
	card := decodeCard(t, body)

	assert.Equal(t, "AdaptiveCard", card.Type)
	assert.Equal(t, adaptiveSchema, card.Schema)
	assert.Equal(t, adaptiveVersion, card.Version)
	assert.Equal(t, map[string]string{"width": "Full"}, card.MSTeams)
	require.Len(t, card.Body, 3)

	header := card.Body[0]
	assert.Equal(t, "Container", header.Type)
	assert.Equal(t, "warning", header.Style)
	require.Len(t, header.Items, 1)
	columns := header.Items[0].Columns
	require.Len(t, columns, 2)
	assert.Equal(t, "Image", columns[0].Items[0].Type)
	assert.Equal(t, defaultActivityImage, columns[0].Items[0].URL)
	heading := columns[1].Items
	require.Len(t, heading, 3)
	assert.Equal(t, cardTitle, heading[0].Text)
	assert.Equal(t, evt.Time.String(), heading[1].Text)
	assert.Equal(t, "error", heading[2].Text)
	assert.Equal(t, "warning", heading[2].Color)

	assert.Equal(t, evt.Output, findText(card))
	assert.Equal(t, []fact{
		{Title: "rule", Value: "Write below binary dir"},
		{Title: "priority", Value: "error"},
		{Title: "source", Value: "syscall"},
		{Title: "hostname", Value: "node-1"},
		{Title: "fd.name", Value: "/bin/hack"},
		{Title: "proc.cmdline", Value: "touch /bin/hack"},
		{Title: "user.name", Value: "root"},
		{Title: "tags", Value: "filesystem, mitre_persistence"},
	}, findFacts(card))
}

func TestPayloadFormats(t *testing.T) {
	for _, tc := range []struct {
		format    string
		wantText  bool
		wantFacts bool
	}{
		{format: formatAll, wantText: true, wantFacts: true},
		{format: formatText, wantText: true},
		{format: formatFields, wantFacts: true},
	} {
		t.Run(tc.format, func(t *testing.T) {
			d := newDriver(t, &config{OutputFormat: tc.format})
			body, err := d.buildPayload(testutil.CreateValidEvent())
			require.NoError(t, err)
			card := decodeCard(t, body)
			assert.Equal(t, tc.wantText, findText(card) != "")
			assert.Equal(t, tc.wantFacts, findFacts(card) != nil)
		})
	}
}

func TestPayloadOptionalFacts(t *testing.T) {
	d := newDriver(t, &config{})
	evt := testutil.CreateValidEvent()
	evt.Hostname = ""
	evt.Tags = nil
	evt.OutputFields = map[string]any{"n": 42}
	body, err := d.buildPayload(evt)
	require.NoError(t, err)
	assert.Equal(t, []fact{
		{Title: "rule", Value: evt.Rule},
		{Title: "priority", Value: "error"},
		{Title: "source", Value: "syscall"},
		{Title: "n", Value: "42"},
	}, findFacts(decodeCard(t, body)))
}

func TestPayloadPriorityStyles(t *testing.T) {
	want := map[event.Priority]string{
		event.PriorityEmergency: "attention", event.PriorityAlert: "attention", event.PriorityCritical: "attention",
		event.PriorityError: "warning", event.PriorityWarning: "warning",
		event.PriorityNotice: "good", event.PriorityInformational: "accent", event.PriorityDebug: "default",
		event.Priority("unknown"): "default",
	}
	d := newDriver(t, &config{})
	for p, style := range want {
		t.Run(string(p), func(t *testing.T) {
			evt := testutil.CreateValidEvent()
			evt.Priority = p
			body, err := d.buildPayload(evt)
			require.NoError(t, err)
			header := decodeCard(t, body).Body[0]
			assert.Equal(t, style, header.Style)
			assert.Equal(t, style, header.Items[0].Columns[1].Items[2].Color)
		})
	}
}

func TestPayloadSizeLimit(t *testing.T) {
	t.Run("long fact values are truncated", func(t *testing.T) {
		d := newDriver(t, &config{})
		evt := testutil.CreateValidEvent()
		evt.OutputFields = map[string]any{"long": strings.Repeat("x", 5000)}
		body, err := d.buildPayload(evt)
		require.NoError(t, err)
		var long *fact
		for _, f := range findFacts(decodeCard(t, body)) {
			if f.Title == "long" {
				long = &f
			}
		}
		require.NotNil(t, long, "the long field is kept, truncated")
		assert.Equal(t, maxFactRunes, len([]rune(long.Value)))
		assert.True(t, strings.HasSuffix(long.Value, "..."))
	})
	t.Run("multi-byte text keeps most of the budget", func(t *testing.T) {
		d := newDriver(t, &config{OutputFormat: formatText})
		evt := testutil.CreateValidEvent()
		evt.Output = strings.Repeat("🔥", 16*1024)
		body, err := d.buildPayload(evt)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(body), maxPayloadBytes)
		text := findText(decodeCard(t, body))
		assert.True(t, utf8.ValidString(text))
		assert.Greater(t, len(text), maxPayloadBytes/2, "emoji are 4 bytes: the cut is measured in bytes, not runes")
	})
	t.Run("output fields dropped before the others", func(t *testing.T) {
		d := newDriver(t, &config{})
		evt := testutil.CreateValidEvent()
		evt.OutputFields = map[string]any{}
		for i := range 100 {
			evt.OutputFields[fmt.Sprintf("field.%03d", i)] = strings.Repeat("v", 900)
		}
		body, err := d.buildPayload(evt)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(body), maxPayloadBytes)
		facts := findFacts(decodeCard(t, body))
		require.Greater(t, len(facts), 5)
		assert.Less(t, len(facts), 105)
		assert.Equal(t, "rule", facts[0].Title)
		assert.Equal(t, "field.000", facts[4].Title)
		assert.Equal(t, "tags", facts[len(facts)-1].Title)
		assert.Equal(t, evt.Output, findText(decodeCard(t, body)))
	})
	t.Run("text cut last", func(t *testing.T) {
		d := newDriver(t, &config{OutputFormat: formatText})
		evt := testutil.CreateValidEvent()
		evt.Output = strings.Repeat("é\"", 20000)
		body, err := d.buildPayload(evt)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(body), maxPayloadBytes)
		text := findText(decodeCard(t, body))
		assert.True(t, strings.HasSuffix(text, "..."))
		assert.Greater(t, len(body), maxPayloadBytes/2, "the cut keeps most of the budget")
	})
	t.Run("all facts dropped when they alone overflow", func(t *testing.T) {
		d := newDriver(t, &config{OutputFormat: formatFields})
		evt := testutil.CreateValidEvent()
		evt.OutputFields = nil
		evt.Rule = strings.Repeat("r", 900)
		evt.Tags = []string{strings.Repeat("t", 900)}
		d.cfg.ActivityImage = "https://img.example/" + strings.Repeat("i", maxPayloadBytes-2000)
		body, err := d.buildPayload(evt)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(body), maxPayloadBytes)
		assert.Less(t, len(findFacts(decodeCard(t, body))), 5)
	})
	t.Run("header alone too large", func(t *testing.T) {
		d := newDriver(t, &config{OutputFormat: formatFields})
		d.cfg.ActivityImage = "https://img.example/" + strings.Repeat("i", maxPayloadBytes)
		_, err := d.buildPayload(testutil.CreateValidEvent())
		require.Error(t, err)
	})
}

func TestSendDelivers(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusAccepted} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, requests := testutil.StartCaptureServer(t, status, "")
			d, err := OutputType.New(baseConfig(server.URL), output.Deps{})
			require.NoError(t, err)
			require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
			req := <-requests
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, testPath, req.URL.Path)
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			assert.Equal(t, testSignature, req.URL.Query().Get("sig"))
			assert.Equal(t, "2016-06-01", req.URL.Query().Get("api-version"))
			card := decodeCard(t, req.Body)
			assert.Equal(t, "AdaptiveCard", card.Type)
		})
	}
}

func TestSendFailuresHideSecrets(t *testing.T) {
	for _, tc := range []struct {
		want   string
		status int
	}{
		{status: http.StatusBadRequest, want: "HTTP 400"},
		{status: http.StatusUnauthorized, want: "HTTP 401"},
		{status: http.StatusNotFound, want: "HTTP 404"},
		{status: http.StatusTooManyRequests, want: "HTTP 429"},
		{status: http.StatusInternalServerError, want: "HTTP 500"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			server, _ := testutil.StartCaptureServer(t, tc.status, "reflected "+testSignature+" "+testPath)
			d, err := OutputType.New(baseConfig(server.URL), output.Deps{})
			require.NoError(t, err)
			err = d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), testSignature)
			assert.NotContains(t, err.Error(), testPath)
			var diagnostic *shared.DeliveryError
			assert.ErrorAs(t, err, &diagnostic)
		})
	}
}

func TestSendUnreachableHidesSecrets(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	d, err := OutputType.New(baseConfig(server.URL), output.Deps{})
	require.NoError(t, err)
	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), testSignature)
	assert.NotContains(t, err.Error(), testPath)
}

func TestSendQueryFileError(t *testing.T) {
	file := t.TempDir() + "/sig"
	require.NoError(t, os.WriteFile(file, []byte(testSignature), 0o600))
	cfg := baseConfig("https://h.example")
	cfg["query_params"] = map[string]any{"sig": map[string]any{"files": []string{file}}}
	d, err := OutputType.New(cfg, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, os.Remove(file))
	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "teams target")
	assert.NotContains(t, err.Error(), testSignature)
}

func TestSendMarshalFailure(t *testing.T) {
	d := newDriver(t, &config{OutputFormat: formatFields})
	d.cfg.ActivityImage = "https://img.example/" + strings.Repeat("i", maxPayloadBytes)
	err := d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "teams marshal")
}

func TestHealthCheckSendsNoRequest(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	cfg := baseConfig(server.URL)
	maps.Copy(cfg, map[string]any{"output_format": "text"})
	d, err := OutputType.New(cfg, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, d.HealthCheck(context.Background()))
	assert.Zero(t, calls, "a probe would run the flow and post a message")
}
