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
	"sync"
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
			require.EqualError(t, err, "elasticsearch response: bulk indexed 1/3, 2 failed")
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
		writeCreated(w, capturedBody)
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
	second.UUID = ""
	secondData, err := d.marshalEvent(second)
	require.NoError(t, err)
	want := `{"create":{"_index":"test","_id":"test-uuid-001"}}` + "\n" + string(firstData) + "\n" +
		`{"create":{"_index":"test"}}` + "\n" + string(secondData) + "\n"

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
		body, _ := io.ReadAll(r.Body)
		writeCreated(w, body)
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
		body, _ := io.ReadAll(r.Body)
		writeCreated(w, body)
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

func TestSendBatchBulkFormatAndIndex(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		writeCreated(w, capturedBody)
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

func writeCreated(w http.ResponseWriter, body []byte) {
	items := make([]string, strings.Count(string(body), "\n")/2)
	for i := range items {
		items[i] = `{"create":{"status":201}}`
	}
	_, _ = w.Write([]byte(`{"errors":false,"items":[` + strings.Join(items, ",") + `]}`))
}

func TestParseBulkResponseAccountsForEveryItem(t *testing.T) {
	const (
		created  = `{"create":{"status":201}}`
		conflict = `{"create":{"status":409,"error":{"type":"version_conflict_engine_exception"}}}`
		mapping  = `{"create":{"status":400,"error":{"type":"document_parsing_exception"}}}`
		rejected = `{"create":{"status":429,"error":{"type":"es_rejected_execution_exception"}}}`
		other409 = `{"create":{"status":409,"error":{"type":"other_exception"}}}`
	)
	for _, tc := range []struct {
		name, body, want string
		expected         int
		permanent        bool
	}{
		{name: "all created", body: `{"errors":false,"items":[` + created + `,` + created + `]}`, expected: 2},
		{name: "already indexed", body: `{"errors":true,"items":[` + conflict + `,` + conflict + `]}`, expected: 2},
		{name: "created and already indexed", body: `{"errors":true,"items":[` + created + `,` + conflict + `]}`, expected: 2},
		{name: "one mapping failure", body: `{"errors":true,"items":[` + created + `,` + mapping + `,` + created + `]}`, expected: 3, want: "elasticsearch response: bulk indexed 2/3, 1 failed", permanent: true},
		{name: "rejected", body: `{"errors":true,"items":[` + rejected + `,` + conflict + `]}`, expected: 2, want: "elasticsearch response: bulk indexed 1/2, 1 failed"},
		{name: "mapping and rejected", body: `{"errors":true,"items":[` + mapping + `,` + rejected + `]}`, expected: 2, want: "elasticsearch response: bulk indexed 0/2, 2 failed"},
		{name: "conflict of another type", body: `{"errors":true,"items":[` + other409 + `]}`, expected: 1, want: "elasticsearch response: bulk indexed 0/1, 1 failed"},
		{name: "item without create", body: `{"errors":true,"items":[{"index":{"status":201}}]}`, expected: 1, want: "elasticsearch response: bulk indexed 0/1, 1 failed"},
		{name: "errors flag hidden", body: `{"items":[` + created + `]}`, expected: 1, want: "incomplete bulk response"},
		{name: "missing items", body: `{"errors":false}`, expected: 1, want: "incomplete bulk response"},
		{name: "short items", body: `{"errors":false,"items":[` + created + `]}`, expected: 2, want: "incomplete bulk response"},
		{name: "empty body", body: ``, expected: 1, want: "invalid JSON"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &driver{logger: slog.New(slog.DiscardHandler)}
			err := d.parseBulkResponse([]byte(tc.body), tc.expected)
			if tc.want == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.Equal(t, tc.permanent, output.IsPermanent(err), "permanent only when every failed item is")
		})
	}
}

// fakeBulkStore models create semantics: a second create of the same _id is a conflict.
type fakeBulkStore struct {
	stored  map[string]int
	failIDs map[string]bool
	mu      sync.Mutex
}

func (f *fakeBulkStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var items []string
	for i := 0; i < len(lines); i += 2 {
		var action struct {
			Create struct {
				ID string `json:"_id"`
			} `json:"create"`
		}
		_ = json.Unmarshal([]byte(lines[i]), &action)
		id := action.Create.ID
		switch {
		case f.failIDs[id]:
			delete(f.failIDs, id)
			items = append(items, `{"create":{"status":429,"error":{"type":"es_rejected_execution_exception"}}}`)
		case f.stored[id] > 0:
			items = append(items, `{"create":{"status":409,"error":{"type":"version_conflict_engine_exception"}}}`)
		default:
			f.stored[id]++
			items = append(items, `{"create":{"status":201}}`)
		}
	}
	_, _ = w.Write([]byte(`{"errors":true,"items":[` + strings.Join(items, ",") + `]}`))
}

func TestSendBatchRetryIndexesEachEventOnce(t *testing.T) {
	store := &fakeBulkStore{stored: map[string]int{}, failIDs: map[string]bool{"b": true}}
	server := httptest.NewServer(store)
	t.Cleanup(server.Close)
	d, err := createOutput(map[string]any{"host": server.URL}, output.Deps{Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	batch := d.(output.BatchSender)

	events := make([]*event.Event, 0, 3)
	for _, id := range []string{"a", "b", "c"} {
		evt := testutil.CreateValidEvent()
		evt.UUID = id
		events = append(events, evt)
	}

	require.EqualError(t, batch.SendBatch(context.Background(), events), "elasticsearch response: bulk indexed 2/3, 1 failed")
	require.NoError(t, batch.SendBatch(context.Background(), events))
	assert.Equal(t, map[string]int{"a": 1, "b": 1, "c": 1}, store.stored)
}
