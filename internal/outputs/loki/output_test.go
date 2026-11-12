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

package loki

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestLokiCommonCases(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "host"},
		{Name: "returns error on server 500", AddressField: "host", MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestLokiPayloadFormat(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{
			Name:         "sets tenant header",
			AddressField: "host",
			Config:       map[string]any{"tenant": "my-org"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "my-org", req.Header.Get("X-Scope-OrgID"))
			},
		},
		{
			Name:         "applies basic auth",
			AddressField: "host",
			Config:       map[string]any{"username": "loki", "password": "secret"},
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				user, pass, ok := req.BasicAuth()
				require.True(t, ok)
				assert.Equal(t, "loki", user)
				assert.Equal(t, "secret", pass)
			},
		},
		{
			Name:         "posts to correct endpoint",
			AddressField: "host",
			ValidateReq: func(t *testing.T, req *http.Request, _ []byte) {
				assert.Equal(t, "/loki/api/v1/push", req.URL.Path)
			},
		},
	})
}

func TestLokiSendUsesGzip(t *testing.T) {
	var capturedEncoding string
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedEncoding = r.Header.Get("Content-Encoding")
		if capturedEncoding == "gzip" {
			gr, err := gzip.NewReader(r.Body)
			if err == nil {
				capturedBody, _ = io.ReadAll(gr)
				_ = gr.Close()
			}
		} else {
			capturedBody, _ = io.ReadAll(r.Body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	o := &driver{
		cfg:    config{HTTPTargetConfig: shared.HTTPTargetConfig{Host: server.URL, Endpoint: defaultEndpoint}, Format: formatJSON},
		sender: testutil.MustNewSender(t, "loki"),
	}

	err := o.Send(context.Background(), testutil.CreateValidEvent())
	require.NoError(t, err)

	assert.Equal(t, "gzip", capturedEncoding, "must send with gzip Content-Encoding")

	var payload lokiPayload
	require.NoError(t, json.Unmarshal(capturedBody, &payload))
	require.Len(t, payload.Streams, 1)
	assert.Equal(t, "Error", payload.Streams[0].Stream["priority"])
}

func TestLokiSendBatchGroupsStreams(t *testing.T) {
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gr, _ := gzip.NewReader(r.Body)
		capturedBody, _ = io.ReadAll(gr)
		_ = gr.Close()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	o := &driver{
		cfg:    config{HTTPTargetConfig: shared.HTTPTargetConfig{Host: server.URL, Endpoint: defaultEndpoint}, Format: formatJSON},
		sender: testutil.MustNewSender(t, "loki"),
	}

	e1 := testutil.CreateValidEvent()
	e2 := testutil.CreateValidEvent()
	e3 := testutil.CreateValidEvent()
	e3.Priority = event.PriorityCritical

	err := o.SendBatch(context.Background(), []*event.Event{e1, e2, e3})
	require.NoError(t, err)

	var payload lokiPayload
	require.NoError(t, json.Unmarshal(capturedBody, &payload))

	assert.Len(t, payload.Streams, 2, "events with different label sets must be in separate streams")

	var defaultStream, criticalStream *lokiStream
	for i := range payload.Streams {
		if payload.Streams[i].Stream["priority"] == event.PriorityError.String() {
			defaultStream = &payload.Streams[i]
		}
		if payload.Streams[i].Stream["priority"] == event.PriorityCritical.String() {
			criticalStream = &payload.Streams[i]
		}
	}

	require.NotNil(t, defaultStream)
	require.NotNil(t, criticalStream)
	assert.Len(t, defaultStream.Values, 2, "same-label events must be grouped into one stream")
	assert.Len(t, criticalStream.Values, 1)
}

func TestLokiCreateValidation(t *testing.T) {
	_, err := createOutput(map[string]any{}, output.Deps{})
	assert.Error(t, err, "missing url must fail")
}

func TestLokiCreateRuntimeDefaults(t *testing.T) {
	d, err := createOutput(map[string]any{"host": testHost}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	assert.Equal(t, defaultEndpoint, o.cfg.Endpoint)
	assert.Equal(t, formatJSON, o.cfg.Format)
}

const testHost = "http://localhost:3100"

func TestLokiFormat(t *testing.T) {
	for _, tc := range []struct {
		cfg     map[string]any
		name    string
		want    string
		wantErr string
	}{
		{name: "text", cfg: map[string]any{"format": "text"}, want: "text"},
		{name: "json", cfg: map[string]any{"format": "json"}, want: formatJSON},
		{name: "unknown", cfg: map[string]any{"format": "logfmt"}, wantErr: "format: must be json/text"},
		{name: "log_format renamed", cfg: map[string]any{"log_format": "text"}, wantErr: "unknown keys: log_format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg["host"] = testHost
			d, err := createOutput(tc.cfg, output.Deps{})
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, d.(*driver).cfg.Format)
		})
	}
}

func TestLokiCreateOutputLabelFields(t *testing.T) {
	d, err := createOutput(map[string]any{
		"host":         testHost,
		"label_fields": []any{"fd.name", "container.name"},
	}, output.Deps{})
	require.NoError(t, err)
	assert.Equal(t, []labelField{{field: "fd.name", label: "fd_name"}, {field: "container.name", label: "container_name"}}, d.(*driver).cfg.labelFields)

	for _, tc := range []struct {
		raw  map[string]any
		name string
		want string
	}{
		{name: "extra_labels is gone", raw: map[string]any{"extra_labels": "fd.name"}, want: "unknown keys"},
		{name: "comma string", raw: map[string]any{"label_fields": "fd.name,user.name"}, want: "label_fields: must be a list"},
		{name: "built-in label", raw: map[string]any{"label_fields": []any{"k8s.ns.name"}}, want: "makes the built-in label k8s_ns_name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.raw["host"] = testHost
			_, err := createOutput(tc.raw, output.Deps{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLokiSendsLabelFields(t *testing.T) {
	testutil.RunOutputTests(t, &OutputType, []testutil.OutputTestCase{
		{
			Name:         "label fields become stream labels",
			AddressField: "host",
			Config:       map[string]any{"label_fields": []any{"user.name"}},
			ValidateReq: func(t *testing.T, _ *http.Request, body []byte) {
				gr, err := gzip.NewReader(bytes.NewReader(body))
				require.NoError(t, err)
				var payload lokiPayload
				require.NoError(t, json.NewDecoder(gr).Decode(&payload))
				require.Len(t, payload.Streams, 1)
				assert.Equal(t, "root", payload.Streams[0].Stream["user_name"])
				assert.Equal(t, "error", payload.Streams[0].Stream["level"])
			},
		},
	})
}

func TestLokiHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ready", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	o := &driver{
		cfg:    config{HTTPTargetConfig: shared.HTTPTargetConfig{Host: server.URL}},
		sender: testutil.MustNewSender(t, "loki"),
	}
	assert.NoError(t, o.HealthCheck(context.Background()))
}

func TestLokiInit(t *testing.T) {
	o := &driver{}
	assert.NoError(t, o.Init(context.Background()))
}

func TestLokiClose(t *testing.T) {
	d, err := OutputType.New(map[string]any{"host": "http://127.0.0.1:1"}, output.Deps{})
	require.NoError(t, err)
	assert.NoError(t, d.Close())
	assert.NoError(t, d.Close(), "Close is idempotent")
}
