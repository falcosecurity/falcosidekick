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

package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestSendBatchSafeErrorLogs(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			var logs bytes.Buffer
			var handler slog.Handler = slog.NewTextHandler(&logs, nil)
			if format == "json" {
				handler = slog.NewJSONHandler(&logs, nil)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"errors":true,"items":[
					{"create":{"status":201}},
					{"create":{"status":400,"error":{"type":"document_parsing_exception","reason":"REASON_SECRET"}}},
					{"create":{"status":429,"error":{"type":"TYPE_SECRET","reason":"REASON_SECRET"}}}
				]}`))
			}))
			t.Cleanup(server.Close)
			d, err := createOutput(map[string]any{"host": server.URL, "base_path": "/PATH_SECRET"}, output.Deps{Logger: slog.New(handler)})
			require.NoError(t, err)
			events := []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent(), testutil.CreateValidEvent()}
			err = d.(output.BatchSender).SendBatch(context.Background(), events)
			require.EqualError(t, err, "elasticsearch: bulk indexed 1/3, 2 failed")
			for _, secret := range []string{"TYPE_SECRET", "REASON_SECRET", "PATH_SECRET"} {
				assert.NotContains(t, logs.String(), secret)
				assert.NotContains(t, err.Error(), secret)
			}
			assert.Contains(t, logs.String(), "document_parsing_exception")
			assert.Contains(t, logs.String(), "unknown error")
			assert.Contains(t, logs.String(), "400")
			assert.Contains(t, logs.String(), "429")
			assert.Contains(t, logs.String(), "bulk request partial failure")
		})
	}
}

func TestClassifyBulkError(t *testing.T) {
	for _, tc := range []struct{ code, want string }{
		{"document_parsing_exception", "document_parsing_exception"},
		{"mapper_parsing_exception", "mapper_parsing_exception"},
		{"es_rejected_execution_exception", "es_rejected_execution_exception"},
		{"version_conflict_engine_exception", "version_conflict_engine_exception"},
		{"index_not_found_exception", "index_not_found_exception"},
		{"", "unknown error"},
		{"es_rejected_execution_exception: SECRET", "unknown error"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyBulkError(tc.code))
		})
	}
}

func TestSendBatchSafeParseErrors(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"syntax", `{"errors":true,"items":SECRET}`, "invalid JSON"},
		{"type", `{"errors":true,"items":[{"create":{"status":"SECRET"}}]}`, "unexpected JSON type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)
			d, err := createOutput(map[string]any{"host": server.URL}, output.Deps{})
			require.NoError(t, err)
			err = d.(output.BatchSender).SendBatch(context.Background(), []*event.Event{testutil.CreateValidEvent()})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), "SECRET")
			var diagnostic *shared.DeliveryError
			assert.ErrorAs(t, err, &diagnostic)
			if tc.name == "syntax" {
				var syntax *json.SyntaxError
				assert.ErrorAs(t, err, &syntax)
			} else {
				var mismatch *json.UnmarshalTypeError
				assert.ErrorAs(t, err, &mismatch)
			}
		})
	}
}

func TestSendBatchUsesCreateAction(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver, err := createOutput(map[string]any{
		"host":         server.URL,
		"index":        "test",
		"index_suffix": "none",
	}, output.Deps{})
	require.NoError(t, err)

	batchDriver, ok := driver.(output.BatchSender)
	require.True(t, ok)

	events := []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()}
	require.NoError(t, batchDriver.SendBatch(context.Background(), events))

	lines := strings.Split(strings.TrimSpace(string(capturedBody)), "\n")
	require.Len(t, lines, 4)

	var action map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &action))
	assert.Contains(t, action, "create", "bulk action must be 'create' (not 'index')")
}

func TestBuildBulkBodyIsExactNDJSON(t *testing.T) {
	created, err := createOutput(map[string]any{
		"host":         "http://127.0.0.1:9200",
		"index":        "test",
		"index_suffix": "none",
	}, output.Deps{})
	require.NoError(t, err)
	d, ok := created.(*driver)
	require.True(t, ok)

	first, second := testutil.CreateValidEvent(), testutil.CreateValidEvent()
	firstData, err := d.marshalEvent(first)
	require.NoError(t, err)
	secondData, err := d.marshalEvent(second)
	require.NoError(t, err)

	const action = `{"create":{"_index":"test"}}`
	want := action + "\n" + string(firstData) + "\n" + action + "\n" + string(secondData) + "\n"

	got, err := d.buildBulkBody([]*event.Event{first, second})
	require.NoError(t, err)
	assert.Equal(t, want, string(got))

	empty, err := d.buildBulkBody(nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestSendBatchIncludesFilterPath(t *testing.T) {
	var capturedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver, err := createOutput(map[string]any{
		"host":         server.URL,
		"index_suffix": "none",
	}, output.Deps{})
	require.NoError(t, err)

	batchDriver := driver.(output.BatchSender)
	require.NoError(t, batchDriver.SendBatch(context.Background(), []*event.Event{testutil.CreateValidEvent()}))

	assert.Contains(t, capturedURL, "filter_path=")
}

func TestSendBatchWithPipeline(t *testing.T) {
	var capturedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver, err := createOutput(map[string]any{
		"host":         server.URL,
		"index_suffix": "none",
		"pipeline":     "enrich",
	}, output.Deps{})
	require.NoError(t, err)

	batchDriver := driver.(output.BatchSender)
	require.NoError(t, batchDriver.SendBatch(context.Background(), []*event.Event{testutil.CreateValidEvent()}))

	assert.Contains(t, capturedURL, "pipeline=enrich")
}

func TestParseBulkResponseAllSuccess(t *testing.T) {
	o := &driver{logger: slog.Default()}
	body := []byte(`{"errors":false,"items":[{"create":{"status":201}},{"create":{"status":201}}]}`)
	assert.NoError(t, o.parseBulkResponse(body, 2))
}

func TestParseBulkResponseEmptyBody(t *testing.T) {
	o := &driver{logger: slog.Default()}
	assert.NoError(t, o.parseBulkResponse(nil, 0))
	assert.NoError(t, o.parseBulkResponse([]byte{}, 0))
}

func TestParseBulkResponsePartialFailure(t *testing.T) {
	o := &driver{logger: slog.Default()}
	body := []byte(`{"errors":true,"items":[
		{"create":{"status":201}},
		{"create":{"status":400,"error":{"type":"document_parsing_exception","reason":"field mapping"}}},
		{"create":{"status":201}}
	]}`)

	err := o.parseBulkResponse(body, 3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2/3")
	assert.Contains(t, err.Error(), "1 failed")
}

func TestParseBulkResponseAllFailed(t *testing.T) {
	o := &driver{logger: slog.Default()}
	body := []byte(`{"errors":true,"items":[
		{"create":{"status":429,"error":{"type":"es_rejected_execution_exception","reason":"queue full"}}},
		{"create":{"status":429,"error":{"type":"es_rejected_execution_exception","reason":"queue full"}}}
	]}`)

	err := o.parseBulkResponse(body, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0/2")
	assert.Contains(t, err.Error(), "2 failed")
}

func TestParseBulkResponseFastPathNoErrors(t *testing.T) {
	o := &driver{logger: slog.Default()}
	// Response without "errors":true - fast path skips JSON parsing.
	body := []byte(`{"errors":false,"items":[{"create":{"status":201}}]}`)
	assert.NoError(t, o.parseBulkResponse(body, 1))
}

func TestSendBatchBulkFormatAndIndex(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver, err := createOutput(map[string]any{
		"host":         server.URL,
		"index":        "alerts",
		"index_suffix": "none",
	}, output.Deps{})
	require.NoError(t, err)

	batchDriver := driver.(output.BatchSender)
	events := []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent(), testutil.CreateValidEvent()}
	require.NoError(t, batchDriver.SendBatch(context.Background(), events))

	lines := strings.Split(strings.TrimSpace(string(capturedBody)), "\n")
	require.Len(t, lines, 6)

	for i := 0; i < len(lines); i += 2 {
		var action map[string]any
		require.NoError(t, json.Unmarshal([]byte(lines[i]), &action))
		create := action["create"].(map[string]any)
		assert.Equal(t, "alerts", create["_index"])

		var doc map[string]any
		require.NoError(t, json.Unmarshal([]byte(lines[i+1]), &doc))
		assert.Contains(t, doc, "@timestamp")
	}
}
