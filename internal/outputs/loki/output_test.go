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
	testutil.RunOutputTests(t, OutputType, []testutil.OutputTestCase{
		{Name: "sends valid event", AddressField: "host"},
		{Name: "returns error on server 500", AddressField: "host", MockStatus: http.StatusInternalServerError, ExpectError: true},
	})
}

func TestLokiPayloadFormat(t *testing.T) {
	testutil.RunOutputTests(t, OutputType, []testutil.OutputTestCase{
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
		cfg:    config{HTTPTargetConfig: shared.HTTPTargetConfig{Host: server.URL, Endpoint: defaultEndpoint}, LogFormat: formatJSON},
		sender: testutil.MustNewSender(t, "loki"),
	}

	err := o.Send(context.Background(), testutil.CreateValidEvent())
	require.NoError(t, err)

	assert.Equal(t, "gzip", capturedEncoding, "must send with gzip Content-Encoding")

	var payload lokiPayload
	require.NoError(t, json.Unmarshal(capturedBody, &payload))
	require.Len(t, payload.Streams, 1)
	assert.NotEmpty(t, payload.Streams[0].Stream["rule"])
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
		cfg:    config{HTTPTargetConfig: shared.HTTPTargetConfig{Host: server.URL, Endpoint: defaultEndpoint}, LogFormat: formatJSON},
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
		if payload.Streams[i].Stream["priority"] == string(event.PriorityError) {
			defaultStream = &payload.Streams[i]
		}
		if payload.Streams[i].Stream["priority"] == string(event.PriorityCritical) {
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
	d, err := createOutput(map[string]any{"host": "http://localhost:3100"}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	assert.Equal(t, defaultEndpoint, o.cfg.Endpoint)
	assert.Equal(t, formatJSON, o.cfg.LogFormat)
}

func TestLokiCreateOutputExtraLabels(t *testing.T) {
	d, err := createOutput(map[string]any{
		"host":         "http://localhost:3100",
		"extra_labels": "fd.name, user.name, ,proc.cmdline",
	}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	assert.Equal(t, []string{"fd.name", "user.name", "proc.cmdline"}, o.extraLabels)
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
