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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	testToken = "WEBHOOK_TOKEN_SECRET"
	testPath  = "/api/webhooks/123456/" + testToken
)

func newDriver(t *testing.T, cfg *config) *driver {
	t.Helper()
	cfg.SecretEndpoint = testPath
	require.Empty(t, cfg.validate())
	return &driver{cfg: *cfg, logger: slog.New(slog.DiscardHandler)}
}

func embedRunes(e embed) int {
	n := utf8.RuneCountInString(e.Description)
	for _, f := range e.Fields {
		n += f.runes()
	}
	return n
}

func TestValidation(t *testing.T) {
	tests := []struct {
		config map[string]any
		name   string
		want   string
	}{
		{name: "minimal", config: map[string]any{"secret_endpoint": testPath}},
		{name: "custom host", config: map[string]any{"host": "https://proxy.example:8443", "secret_endpoint": testPath}},
		{name: "missing secret_endpoint", config: map[string]any{}, want: "secret_endpoint: is required"},
		{name: "public endpoint rejected", config: map[string]any{"secret_endpoint": testPath, "endpoint": "/x"}, want: "endpoint: is not supported"},
		{name: "host with path rejected", config: map[string]any{"host": "https://discord.com" + testPath, "secret_endpoint": testPath}, want: "host"},
		{name: "unknown key", config: map[string]any{"secret_endpoint": testPath, "webhook_url": "x"}, want: "webhook_url"},
		{name: "minimum priority is a runtime key", config: map[string]any{"secret_endpoint": testPath, "minimum_priority": "error"}, want: "minimum_priority"},
		{name: "invalid icon", config: map[string]any{"secret_endpoint": testPath, "icon": "ftp://x/y.png"}, want: "icon: must be an absolute http or https URL"},
		{name: "relative icon", config: map[string]any{"secret_endpoint": testPath, "icon": "y.png"}, want: "icon"},
		{name: "invalid tls", config: map[string]any{"secret_endpoint": testPath, "tls": map[string]any{"ca_file": "/does/not/exist"}}, want: "tls"},
		{name: "wait is set by the output", config: map[string]any{"secret_endpoint": testPath,
			"query_params": map[string]any{"wait": map[string]any{"values": []string{"false"}}}}, want: `query_params["wait"]: is set by the output`},
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
			assert.NotContains(t, err.Error(), testToken)
		})
	}
}

func TestDefaults(t *testing.T) {
	d, err := OutputType.New(map[string]any{"secret_endpoint": testPath}, output.Deps{})
	require.NoError(t, err)
	o := d.(*driver)
	assert.Equal(t, "https://discord.com", o.cfg.Host)
	assert.Equal(t, defaultIcon, o.cfg.Icon)
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
	assert.Equal(t, "https://discord.com", fields["host"].Default)
	assert.False(t, fields["host"].Required)
	assert.NotContains(t, fields, "endpoint")
	assert.Equal(t, defaultIcon, fields["icon"].Default)
	assert.Contains(t, fields, "runtime.minimum_priority")
	assert.Equal(t, output.CategoryChat, OutputType.Category)
}

func TestPayloadV2Parity(t *testing.T) {
	d := newDriver(t, &config{Icon: "https://img.example/a.png"})
	evt := testutil.CreateValidEvent()
	p := d.buildPayload(evt)

	body, err := json.Marshal(p)
	require.NoError(t, err)
	assert.NotContains(t, string(body), `"content"`)
	assert.Equal(t, "https://img.example/a.png", p.AvatarURL)
	require.Len(t, p.Embeds, 1)
	e := p.Embeds[0]
	assert.Equal(t, evt.Output, e.Description)
	assert.Equal(t, 15844367, e.Color)
	assert.Equal(t, []field{
		{Name: "rule", Value: "Write below binary dir", Inline: true},
		{Name: "priority", Value: "error", Inline: true},
		{Name: "source", Value: "syscall", Inline: true},
		{Name: "hostname", Value: "node-1", Inline: true},
		{Name: "fd.name", Value: "```/bin/hack```", Inline: true},
		{Name: "proc.cmdline", Value: "```touch /bin/hack```", Inline: true},
		{Name: "user.name", Value: "```root```", Inline: true},
		{Name: "tags", Value: "filesystem, mitre_persistence", Inline: true},
		{Name: "time", Value: evt.Time.String(), Inline: true},
	}, e.Fields)
}

func TestPayloadOptionalFields(t *testing.T) {
	d := newDriver(t, &config{})
	evt := testutil.CreateValidEvent()
	evt.Hostname = ""
	evt.Tags = nil
	evt.Output = ""
	evt.OutputFields = map[string]any{"n": 42}
	p := d.buildPayload(evt)
	names := make([]string, 0, len(p.Embeds[0].Fields))
	for _, f := range p.Embeds[0].Fields {
		names = append(names, f.Name)
	}
	assert.Equal(t, []string{"rule", "priority", "source", "n", "time"}, names)
	assert.Equal(t, "```42```", p.Embeds[0].Fields[3].Value)
	body, err := json.Marshal(p)
	require.NoError(t, err)
	assert.NotContains(t, string(body), `"description"`)
}

func TestPayloadPriorityColors(t *testing.T) {
	want := map[event.Priority]int{
		event.PriorityEmergency: 15158332, event.PriorityAlert: 11027200, event.PriorityCritical: 15105570,
		event.PriorityError: 15844367, event.PriorityWarning: 12745742, event.PriorityNotice: 3066993,
		event.PriorityInformational: 3447003, event.PriorityDebug: 12370112, event.Priority("unknown"): 12370112,
	}
	d := newDriver(t, &config{})
	for p, color := range want {
		t.Run(string(p), func(t *testing.T) {
			evt := testutil.CreateValidEvent()
			evt.Priority = p
			assert.Equal(t, color, d.buildPayload(evt).Embeds[0].Color)
		})
	}
}

func TestPayloadLimits(t *testing.T) {
	t.Run("field count", func(t *testing.T) {
		d := newDriver(t, &config{})
		evt := testutil.CreateValidEvent()
		evt.OutputFields = map[string]any{}
		for i := range 40 {
			evt.OutputFields[fmt.Sprintf("f%02d", i)] = "v"
		}
		e := d.buildPayload(evt).Embeds[0]
		require.Len(t, e.Fields, maxFields)
		assert.Equal(t, "f00", e.Fields[4].Name)
		assert.Equal(t, "f18", e.Fields[22].Name)
		assert.Equal(t, "tags", e.Fields[23].Name)
		assert.Equal(t, "time", e.Fields[24].Name)
	})
	t.Run("field lengths", func(t *testing.T) {
		d := newDriver(t, &config{})
		evt := testutil.CreateValidEvent()
		evt.Rule = strings.Repeat("r", 2000)
		evt.OutputFields = map[string]any{strings.Repeat("k", 300): strings.Repeat("v", 2000)}
		e := d.buildPayload(evt).Embeds[0]
		for _, f := range e.Fields {
			assert.LessOrEqual(t, utf8.RuneCountInString(f.Name), maxFieldNameRunes)
			assert.LessOrEqual(t, utf8.RuneCountInString(f.Value), maxFieldValueRunes)
		}
		assert.True(t, strings.HasPrefix(e.Fields[4].Value, codeFence))
		assert.True(t, strings.HasSuffix(e.Fields[4].Value, "..."+codeFence))
	})
	t.Run("description length", func(t *testing.T) {
		d := newDriver(t, &config{})
		evt := testutil.CreateValidEvent()
		evt.OutputFields = nil
		evt.Output = strings.Repeat("é", 5000)
		e := d.buildPayload(evt).Embeds[0]
		assert.Equal(t, maxDescriptionRunes, utf8.RuneCountInString(e.Description))
	})
	t.Run("total characters", func(t *testing.T) {
		d := newDriver(t, &config{})
		evt := testutil.CreateValidEvent()
		evt.Output = strings.Repeat("o", 5000)
		evt.OutputFields = map[string]any{}
		for i := range 10 {
			evt.OutputFields[fmt.Sprintf("f%d", i)] = strings.Repeat("v", 500)
		}
		e := d.buildPayload(evt).Embeds[0]
		assert.LessOrEqual(t, embedRunes(e), maxEmbedRunes)
		assert.Equal(t, maxDescriptionRunes, utf8.RuneCountInString(e.Description))
		assert.Equal(t, "time", e.Fields[len(e.Fields)-1].Name)
		assert.Less(t, len(e.Fields), 16, "output fields beyond the budget are dropped")
	})
	t.Run("long fixed fields shorten the description", func(t *testing.T) {
		d := newDriver(t, &config{})
		evt := testutil.CreateValidEvent()
		evt.Output = strings.Repeat("o", 5000)
		evt.Rule = strings.Repeat("r", 1500)
		evt.Source = strings.Repeat("s", 1500)
		evt.Tags = []string{strings.Repeat("t", 1500)}
		e := d.buildPayload(evt).Embeds[0]
		assert.LessOrEqual(t, embedRunes(e), maxEmbedRunes)
		assert.Less(t, utf8.RuneCountInString(e.Description), maxDescriptionRunes)
	})
}

func TestSendDelivers(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, requests := testutil.StartCaptureServer(t, status, "")
			d, err := OutputType.New(map[string]any{"host": server.URL, "secret_endpoint": testPath}, output.Deps{})
			require.NoError(t, err)
			require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
			req := <-requests
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, testPath, req.URL.Path)
			assert.Equal(t, "true", req.URL.Query().Get("wait"), "Discord confirms the saved message")
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			var p payload
			require.NoError(t, json.Unmarshal(req.Body, &p))
			require.Len(t, p.Embeds, 1)
			assert.Equal(t, defaultIcon, p.AvatarURL)
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
			server, _ := testutil.StartCaptureServer(t, tc.status, `{"message": "Invalid Webhook Token `+testToken+`", "code": 50027}`)
			d, err := OutputType.New(map[string]any{"host": server.URL, "secret_endpoint": testPath}, output.Deps{})
			require.NoError(t, err)
			err = d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), testToken)
			var diagnostic *shared.DeliveryError
			assert.ErrorAs(t, err, &diagnostic)
		})
	}
}

func TestSendUnreachableHidesSecrets(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	d, err := OutputType.New(map[string]any{"host": server.URL, "secret_endpoint": testPath}, output.Deps{})
	require.NoError(t, err)
	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), testToken)
}

func TestSendQueryFileError(t *testing.T) {
	file := t.TempDir() + "/thread"
	require.NoError(t, os.WriteFile(file, []byte("42"), 0o600))
	d, err := OutputType.New(map[string]any{
		"secret_endpoint": testPath,
		"query_params":    map[string]any{"thread_id": map[string]any{"files": []string{file}}},
	}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, os.Remove(file))
	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "discord target")
	assert.NotContains(t, err.Error(), testToken)
}

// The probe reads the webhook with GET; it must never POST a message.
func TestHealthCheck(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		misconfigured bool
	}{
		{name: "webhook exists", status: http.StatusOK},
		{name: "wrong token", status: http.StatusUnauthorized, misconfigured: true},
		{name: "deleted webhook", status: http.StatusNotFound, misconfigured: true},
		{name: "rate limited", status: http.StatusTooManyRequests},
		{name: "unavailable", status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var method, path string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				method, path = r.Method, r.URL.Path
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			d, err := OutputType.New(map[string]any{"host": server.URL, "secret_endpoint": testPath}, output.Deps{})
			require.NoError(t, err)

			err = d.HealthCheck(context.Background())
			assert.Equal(t, http.MethodGet, method)
			assert.Equal(t, testPath, path)
			if tc.status == http.StatusOK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tc.misconfigured, errors.Is(err, output.ErrMisconfigured))
			assert.NotContains(t, err.Error(), testToken)
		})
	}
}
