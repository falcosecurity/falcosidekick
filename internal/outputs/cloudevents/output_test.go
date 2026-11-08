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

package cloudevents

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func newDriver(t *testing.T, cfg map[string]any) *driver {
	t.Helper()
	d, err := OutputType.New(cfg, output.Deps{})
	require.NoError(t, err)
	return d.(*driver)
}

func TestSchema(t *testing.T) {
	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		fields[f.Name] = f
	}
	assert.True(t, fields["host"].Required)
	assert.Equal(t, "/", fields["endpoint"].Default)
	assert.True(t, fields["secret_endpoint"].Secret)
	assert.Equal(t, defaultSource, fields["source"].Default)
	assert.Equal(t, "map", fields["extensions"].Type)
	assert.True(t, fields["password"].Secret)
	assert.True(t, fields["bearer_token"].Secret)
}

func TestValidation(t *testing.T) {
	const sentinel = "ce-s3cret-sentinel"
	tests := []struct {
		cfg  map[string]any
		name string
		want string
	}{
		{name: "missing host", cfg: map[string]any{}, want: "host"},
		{name: "invalid host", cfg: map[string]any{"host": "ftp://u:" + sentinel + "@h"}, want: "host: scheme must be http or https"},
		{name: "endpoint and secret_endpoint", cfg: map[string]any{"endpoint": "/a", "secret_endpoint": "/" + sentinel}, want: "endpoint: cannot be combined"},
		{name: "source with control character", cfg: map[string]any{"source": "https://falco.org/\n"}, want: "source: must not contain control characters"},
		{name: "source not a URI reference", cfg: map[string]any{"source": "http://[::1"}, want: "source: must be a URI reference"},
		{name: "extension uppercase", cfg: map[string]any{"extensions": map[string]any{"Team": "a"}}, want: `extensions["Team"]: name must contain only`},
		{name: "extension dash", cfg: map[string]any{"extensions": map[string]any{"my-ext": "a"}}, want: `extensions["my-ext"]: name must contain only`},
		{name: "extension underscore", cfg: map[string]any{"extensions": map[string]any{"my_ext": "a"}}, want: "name must contain only"},
		{name: "extension empty name", cfg: map[string]any{"extensions": map[string]any{"": "a"}}, want: "name must contain only"},
		{name: "extension id", cfg: map[string]any{"extensions": map[string]any{"id": "a"}}, want: `extensions["id"]: name is a CloudEvents context attribute`},
		{name: "extension specversion", cfg: map[string]any{"extensions": map[string]any{"specversion": "a"}}, want: "context attribute"},
		{name: "extension data", cfg: map[string]any{"extensions": map[string]any{"data": "a"}}, want: "context attribute"},
		{name: "extension value control character", cfg: map[string]any{"extensions": map[string]any{"team": "a\x01"}}, want: "value must not contain control characters"},
		{name: "extension value C1 control", cfg: map[string]any{"extensions": map[string]any{"team": "a\u0085"}}, want: "value must not contain control characters"},
		{name: "ce header", cfg: map[string]any{"headers": map[string]any{"Ce-Type": map[string]any{"values": []string{"x"}}}}, want: "is set by the output"},
		{name: "content type header", cfg: map[string]any{"headers": map[string]any{"content-type": map[string]any{"values": []string{"text/plain"}}}}, want: "is set by the output"},
		{name: "unknown key", cfg: map[string]any{"address": "https://h"}, want: "unknown keys: address"},
		{name: "invalid ca file", cfg: map[string]any{"tls": map[string]any{"ca_file": "/nonexistent/ca.pem"}}, want: "ca_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := tt.cfg["host"]; !ok && tt.name != "missing host" {
				tt.cfg["host"] = "https://receiver.example"
			}
			d, err := OutputType.New(tt.cfg, output.Deps{})
			require.Error(t, err)
			assert.Nil(t, d)
			assert.Contains(t, err.Error(), tt.want)
			assert.Contains(t, err.Error(), "cloudevents")
			assert.NotContains(t, err.Error(), sentinel)
		})
	}
}

func TestValidExtensions(t *testing.T) {
	d := newDriver(t, map[string]any{
		"host":       "https://receiver.example",
		"extensions": map[string]any{"team": "secops", "cluster01": "prod east", "averyveryverylongname": "x", "priority": "custom"},
	})
	assert.Len(t, d.cfg.Extensions, 4)
	assert.Equal(t, defaultSource, d.cfg.Source)
	assert.Equal(t, "/", d.cfg.Endpoint)
}

func TestRuntimeOverrides(t *testing.T) {
	d := newDriver(t, map[string]any{"host": "https://receiver.example", "runtime": map[string]any{"minimum_priority": "notice"}})
	assert.Equal(t, event.PriorityNotice, d.RuntimeConfig().MinPriority)
	assert.Equal(t, "cloudevents", d.Name())
	assert.NoError(t, d.Init(context.Background()))
	assert.NoError(t, d.Close())
}

func TestSendBinaryMode(t *testing.T) {
	rec, server := testutil.NewRecorder(t, http.StatusAccepted, "")
	d := newDriver(t, map[string]any{
		"host": server.URL, "base_path": "/base", "endpoint": "/events",
		"source":     "/falco/node-1",
		"extensions": map[string]any{"team": "sec ops", "rule": "overridden"},
		"headers":    map[string]any{"X-Extra": map[string]any{"values": []string{"yes"}}},
	})
	evt := testutil.CreateValidEvent()

	require.NoError(t, d.Send(context.Background(), evt))

	reqs := rec.Received()
	require.Len(t, reqs, 1)
	got := reqs[0]
	assert.Equal(t, http.MethodPost, got.Method)
	assert.Equal(t, "/base/events", got.URL.Path)
	assert.Equal(t, "application/json", got.Header.Get("Content-Type"))
	assert.Empty(t, got.Header.Values("Ce-Datacontenttype"), "binary mode carries the content type in Content-Type")
	assert.Equal(t, "yes", got.Header.Get("X-Extra"))

	want := map[string]string{
		"Ce-Specversion": "1.0",
		"Ce-Id":          "test-uuid-001",
		"Ce-Source":      "/falco/node-1",
		"Ce-Type":        "falco.rule.output.v1",
		"Ce-Time":        "2026-04-01T10:30:00Z",
		"Ce-Priority":    "Error",
		"Ce-Rule":        "overridden",
		"Ce-Eventsource": "syscall",
		"Ce-Hostname":    "node-1",
		"Ce-Team":        "sec%20ops",
	}
	ceHeaders := map[string]string{}
	for key := range got.Header {
		if strings.HasPrefix(key, "Ce-") {
			ceHeaders[key] = got.Header.Get(key)
		}
	}
	assert.Equal(t, want, ceHeaders)

	var body map[string]any
	require.NoError(t, json.Unmarshal(got.Body, &body))
	assert.Equal(t, "Write below binary dir", body["rule"])
	assert.Equal(t, "test-uuid-001", body["uuid"])
	assert.Equal(t, "Error", body["priority"], "the data is the event as Falco sends it")
	assert.Equal(t, "/bin/hack", body["output_fields"].(map[string]any)["fd.name"])
}

func TestSendDefaults(t *testing.T) {
	rec, server := testutil.NewRecorder(t, http.StatusOK, "")
	d := newDriver(t, map[string]any{"host": server.URL})
	evt := testutil.CreateValidEvent()
	evt.UUID, evt.Hostname = "", ""
	evt.Rule = `Read "sensitive" 100% file`
	evt.Time = time.Date(2026, 4, 1, 12, 30, 0, 5, time.FixedZone("CEST", 2*3600))

	require.NoError(t, d.Send(context.Background(), evt))

	reqs := rec.Received()
	require.Len(t, reqs, 1)
	h := reqs[0].Header
	assert.Equal(t, "/", reqs[0].URL.Path)
	assert.Equal(t, defaultSource, h.Get("Ce-Source"))
	_, err := uuid.Parse(h.Get("Ce-Id"))
	assert.NoError(t, err, "an event without uuid gets a generated id")
	assert.Equal(t, "2026-04-01T10:30:00.000000005Z", h.Get("Ce-Time"))
	assert.Empty(t, h.Values("Ce-Hostname"))
	assert.Equal(t, "Read%20%22sensitive%22%20100%25%20file", h.Get("Ce-Rule"))
	decoded, err := url.PathUnescape(h.Get("Ce-Rule"))
	require.NoError(t, err)
	assert.Equal(t, evt.Rule, decoded)
}

func TestSendSecretEndpoint(t *testing.T) {
	const token = "tok-s3cret"
	rec, server := testutil.NewRecorder(t, http.StatusNoContent, "")
	d := newDriver(t, map[string]any{"host": server.URL, "secret_endpoint": "/hooks/" + token})
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	reqs := rec.Received()
	require.Len(t, reqs, 1)
	assert.Equal(t, "/hooks/"+token, reqs[0].URL.Path)

	_, failing := testutil.NewRecorder(t, http.StatusInternalServerError, "unknown hook /hooks/"+token)
	d = newDriver(t, map[string]any{"host": failing.URL, "secret_endpoint": "/hooks/" + token})
	err := d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), token)
}

func TestSendErrors(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			_, server := testutil.NewRecorder(t, status, "invalid token bearer-s3cret")
			d := newDriver(t, map[string]any{"host": server.URL, "bearer_token": "bearer-s3cret"})
			err := d.Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "cloudevents response: HTTP")
			assert.NotContains(t, err.Error(), "bearer-s3cret")
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		d := newDriver(t, map[string]any{"host": "http://127.0.0.1:1"})
		assert.Error(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	})

	t.Run("canceled context", func(t *testing.T) {
		_, server := testutil.NewRecorder(t, http.StatusOK, "")
		d := newDriver(t, map[string]any{"host": server.URL})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.Error(t, d.Send(ctx, testutil.CreateValidEvent()))
	})

	t.Run("unmarshalable output field", func(t *testing.T) {
		d := newDriver(t, map[string]any{"host": "http://127.0.0.1:1"})
		evt := testutil.CreateValidEvent()
		evt.OutputFields["bad"] = make(chan int)
		err := d.Send(context.Background(), evt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cloudevents marshal")
	})
}

func TestHealthCheckSendsNothing(t *testing.T) {
	rec, server := testutil.NewRecorder(t, http.StatusOK, "")
	d := newDriver(t, map[string]any{"host": server.URL})
	assert.NoError(t, d.HealthCheck(context.Background()))
	assert.Empty(t, rec.Received(), "any request may be taken as an event")

	unreachable := newDriver(t, map[string]any{"host": "http://127.0.0.1:1"})
	assert.NoError(t, unreachable.HealthCheck(context.Background()))
}

func TestEventAttributesAreCloudEventsStrings(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Rule = "rule\nwith\tcontrols\x7f\u0085"
	evt.Hostname = "host\xffname"
	evt.Source = "src￾"
	attrs := attributes(evt, "https://falco.org", nil)
	assert.Equal(t, "rule with controls  ", attrs["rule"])
	assert.Equal(t, "host name", attrs["hostname"])
	assert.Equal(t, "src ", attrs["eventsource"])
	assert.Equal(t, "café ✓", ceString("café ✓"), "valid characters are kept")
}

func TestEncodeHeaderValue(t *testing.T) {
	tests := [][2]string{
		{"", ""},
		{"plain-ASCII_~!", "plain-ASCII_~!"},
		{"a b", "a%20b"},
		{`"q"`, "%22q%22"},
		{"100%", "100%25"},
		{"tab\there", "tab%09here"},
		{"del\x7f", "del%7F"},
		{"café", "caf%C3%A9"},
		{"€", "%E2%82%AC"},
		{"https://a/b?c=d", "https://a/b?c=d"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt[1], encodeHeaderValue(tt[0]), tt[0])
	}
}
