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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// --- splitCSV ---

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "foo", []string{"foo"}},
		{"multiple", "foo,bar,baz", []string{"foo", "bar", "baz"}},
		{"trim spaces", " foo , bar ,baz", []string{"foo", "bar", "baz"}},
		{"drop empties", "foo,,bar", []string{"foo", "bar"}},
		{"only empties", ",,,", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, splitCSV(tt.in))
		})
	}
}

// --- /api/v1/events/search ---

func TestHandleEventsSearch_Defaults(t *testing.T) {
	store := &fakeReadableStore{}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/search", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, int32(1), store.SearchCalls.Load())
	require.NotNil(t, store.LastSearchQuery)
	assert.Equal(t, 100, store.LastSearchQuery.Limit)
	assert.Equal(t, 1, store.LastSearchQuery.Page)
	assert.Equal(t, "timestamp", store.LastSearchQuery.SortBy)
	assert.True(t, store.LastSearchQuery.SortDesc)
}

func TestHandleEventsSearch_ParsesAllFilters(t *testing.T) {
	store := &fakeReadableStore{}
	srv := buildTestServerWithStore(t, store)

	url := "/api/v1/events/search?filter=hello" +
		"&priority=critical,error" +
		"&rule=foo,bar" +
		"&source=syscall" +
		"&hostname=node-1,node-2" +
		"&tags=a,b" +
		"&since=30m" +
		"&page=3&limit=25"

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	q := store.LastSearchQuery
	require.NotNil(t, q)
	assert.Equal(t, "hello", q.Filters.Filter)
	assert.Equal(t, []string{"critical", "error"}, q.Filters.Priority)
	assert.Equal(t, []string{"foo", "bar"}, q.Filters.Rule)
	assert.Equal(t, []string{"syscall"}, q.Filters.Source)
	assert.Equal(t, []string{"node-1", "node-2"}, q.Filters.Hostname)
	assert.Equal(t, []string{"a", "b"}, q.Filters.Tags)
	assert.Equal(t, 30*time.Minute, q.Filters.Since)
	assert.Equal(t, 25, q.Limit)
	assert.Equal(t, 3, q.Page)
}

func TestHandleEventsSearch_InvalidPage(t *testing.T) {
	srv := buildTestServerWithStore(t, &fakeReadableStore{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/search?page=abc", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "invalid page")
}

func TestHandleEventsSearch_InvalidLimit(t *testing.T) {
	srv := buildTestServerWithStore(t, &fakeReadableStore{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/search?limit=abc", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode)
}

func TestHandleEventsSearch_InvalidSince(t *testing.T) {
	srv := buildTestServerWithStore(t, &fakeReadableStore{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/search?since=forever", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "invalid since")
}

func TestHandleEventsSearch_NoEventSource(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/search", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandleEventsSearch_StoreError(t *testing.T) {
	store := &fakeReadableStore{
		SearchFn: func(_ context.Context, _ *output.SearchQuery) (*output.SearchResult, error) {
			return nil, errors.New("boom")
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/search", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "boom")
}

// --- /api/v1/events/count ---

func TestHandleEventsCount(t *testing.T) {
	store := &fakeReadableStore{
		CountFn: func(_ context.Context, _ *output.Filters) (int64, error) {
			return 42, nil
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count?priority=error", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got map[string]int64
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, int64(42), got["count"])
}

func TestHandleEventsCount_InvalidFilter(t *testing.T) {
	srv := buildTestServerWithStore(t, &fakeReadableStore{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count?since=nope", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode)
}

func TestHandleEventsCount_NoEventSource(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandleEventsCountBy_NoEventSource(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count/priority", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandleEventsCount_HonorsFreeTextFilter(t *testing.T) {
	store := &fakeReadableStore{}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count?filter=bash&priority=error", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	require.NotNil(t, store.LastCountFilters)
	assert.Equal(t, "bash", store.LastCountFilters.Filter, "count handler must propagate free-text filter= to the store")
	assert.Equal(t, []string{"error"}, store.LastCountFilters.Priority)
}

func TestHandleEventsCount_StoreError(t *testing.T) {
	store := &fakeReadableStore{
		CountFn: func(_ context.Context, _ *output.Filters) (int64, error) {
			return 0, errors.New("bad count")
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

// --- /api/v1/events/count/:groupby ---

func TestHandleEventsCountBy_Valid(t *testing.T) {
	store := &fakeReadableStore{
		CountByFn: func(_ context.Context, _ string, _ *output.Filters) (map[string]int64, error) {
			return map[string]int64{"critical": 3, "error": 7}, nil
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count/priority", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "priority", store.LastCountByField)

	var got struct {
		Groups map[string]int64 `json:"groups"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, int64(3), got.Groups["critical"])
	assert.Equal(t, int64(7), got.Groups["error"])
}

func TestHandleEventsCountBy_HonorsFreeTextFilter(t *testing.T) {
	captured := &struct {
		filters *output.Filters
		field   string
	}{}
	store := &fakeReadableStore{
		CountByFn: func(_ context.Context, field string, f *output.Filters) (map[string]int64, error) {
			captured.field = field
			captured.filters = f
			return map[string]int64{"error": 1}, nil
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count/priority?filter=bash&rule=exec", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "priority", captured.field)
	require.NotNil(t, captured.filters)
	assert.Equal(t, "bash", captured.filters.Filter, "countBy handler must propagate free-text filter= to the store")
	assert.Equal(t, []string{"exec"}, captured.filters.Rule)
}

func TestHandleEventsCountBy_InvalidField(t *testing.T) {
	srv := buildTestServerWithStore(t, &fakeReadableStore{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count/not-a-field", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "not-a-field")
}

func TestHandleEventsCountBy_EmptyGroupsSerialization(t *testing.T) {
	store := &fakeReadableStore{
		CountByFn: func(_ context.Context, _ string, _ *output.Filters) (map[string]int64, error) {
			return nil, nil
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/count/priority", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"groups":{}`, "nil map must serialize as empty object, not null")
}

// --- /api/v1/events/:uuid ---

func TestHandleEventByUUID_Hit(t *testing.T) {
	want := &event.Event{
		UUID:         "abc-123",
		Rule:         "r",
		Priority:     event.PriorityWarning,
		Time:         time.Now().UTC(),
		Source:       "syscall",
		OutputFields: map[string]any{"k": "v"},
	}
	store := &fakeReadableStore{
		GetEventFn: func(_ context.Context, _ string) (*event.Event, error) {
			return want, nil
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/abc-123", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "abc-123", store.LastGetEventUUID)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"uuid":"abc-123"`)
}

func TestHandleEventByUUID_Miss(t *testing.T) {
	store := &fakeReadableStore{
		GetEventFn: func(_ context.Context, _ string) (*event.Event, error) {
			return nil, nil
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/missing", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 404, resp.StatusCode)
}

func TestHandleEventByUUID_EmptyUUIDDomainError(t *testing.T) {
	store := &fakeReadableStore{
		GetEventFn: func(_ context.Context, _ string) (*event.Event, error) {
			return nil, output.ErrEmptyUUID
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/x", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode)
}

func TestHandleEventByUUID_StoreError(t *testing.T) {
	store := &fakeReadableStore{
		GetEventFn: func(_ context.Context, _ string) (*event.Event, error) {
			return nil, errors.New("lookup failed")
		},
	}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/x", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "lookup failed")
}

func TestHandleEventByUUID_NoEventSource(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/x", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandleEventsHistogram_InvalidSince(t *testing.T) {
	srv := buildTestServerWithStore(t, &fakeReadableStore{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/histogram?since=garbage&bucket_ms=60000", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode)
}

func TestHandleEventsHistogram_PassesAllParams(t *testing.T) {
	store := &fakeReadableStore{
		HistogramFn: func(_ context.Context, req *output.HistogramRequest) (*output.HistogramResult, error) {
			return &output.HistogramResult{
				BucketMs: req.BucketMs,
				GroupBy:  req.GroupBy,
				From:     1_700_000_000_000,
				To:       1_700_003_600_000,
				Buckets: []output.HistogramBucket{
					{T: 1_700_000_000_000, Count: 3, By: map[string]int64{"syscall": 3}},
				},
			}, nil
		},
	}
	srv := buildTestServerWithStore(t, store)

	url := "/api/v1/events/histogram?filter=needle" +
		"&priority=error,warning" +
		"&rule=r1,r2" +
		"&source=syscall" +
		"&hostname=node-a" +
		"&tags=x,y" +
		"&since=1h" +
		"&bucket_ms=1800000" +
		"&group_by=source"

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)

	last := store.LastHistogramReq
	require.NotNil(t, last)
	assert.Equal(t, int64(1_800_000), last.BucketMs)
	assert.Equal(t, "source", last.GroupBy)
	assert.Equal(t, "needle", last.Filters.Filter)
	assert.Equal(t, []string{"error", "warning"}, last.Filters.Priority)
	assert.Equal(t, []string{"r1", "r2"}, last.Filters.Rule)
	assert.Equal(t, []string{"syscall"}, last.Filters.Source)
	assert.Equal(t, []string{"node-a"}, last.Filters.Hostname)
	assert.Equal(t, []string{"x", "y"}, last.Filters.Tags)
	assert.Equal(t, time.Hour, last.Filters.Since)
}

func TestHandleEventsHistogram_Valid(t *testing.T) {
	store := &fakeReadableStore{
		HistogramFn: func(_ context.Context, req *output.HistogramRequest) (*output.HistogramResult, error) {
			return &output.HistogramResult{
				BucketMs: req.BucketMs,
				From:     1_000,
				To:       1_000 + 2*req.BucketMs,
				GroupBy:  req.GroupBy,
				Buckets: []output.HistogramBucket{
					{T: 1_000, Count: 3, By: map[string]int64{"syscall": 3}},
					{T: 1_000 + req.BucketMs, Count: 5, By: map[string]int64{"syscall": 4, "k8s_audit": 1}},
				},
			}, nil
		},
	}
	srv := buildTestServerWithStore(t, store)

	url := "/api/v1/events/histogram?since=1h&bucket_ms=900000&group_by=source&priority=error"
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	require.NotNil(t, store.LastHistogramReq)
	assert.Equal(t, int64(900_000), store.LastHistogramReq.BucketMs)
	assert.Equal(t, "source", store.LastHistogramReq.GroupBy)
	assert.Equal(t, time.Hour, store.LastHistogramReq.Filters.Since)
	assert.Equal(t, []string{"error"}, store.LastHistogramReq.Filters.Priority)

	body := struct {
		GroupBy  string                   `json:"group_by"`
		Buckets  []output.HistogramBucket `json:"buckets"`
		BucketMs int64                    `json:"bucket_ms"`
	}{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "source", body.GroupBy)
	assert.Len(t, body.Buckets, 2)
	assert.Equal(t, int64(5), body.Buckets[1].Count)
	assert.Equal(t, int64(4), body.Buckets[1].By["syscall"])
}

func TestHandleEventsHistogram_MissingBucketMs(t *testing.T) {
	store := &fakeReadableStore{}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/histogram?since=1h", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "bucket_ms")
}

func TestHandleEventsHistogram_InvalidBucketMs(t *testing.T) {
	store := &fakeReadableStore{}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/histogram?since=1h&bucket_ms=abc", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode)
}

func TestHandleEventsHistogram_InvalidBucketWindow(t *testing.T) {
	store := &fakeReadableStore{}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/histogram?since=1m&bucket_ms=900000", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 400, resp.StatusCode, "domain-layer validation (since < bucket) must surface as 400 not 500")
}

func TestHandleEventsHistogram_NoEventSource(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/histogram?since=1h&bucket_ms=900000", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandleEventsHistogram_ValidatesBeforeStore(t *testing.T) {
	for _, query := range []string{
		"since=1h&bucket_ms=18446744133710",
		"since=1h&bucket_ms=9223372036854775807",
		"since=1h&bucket_ms=-1",
		"since=1h&bucket_ms=0",
		"since=1h&bucket_ms=999",
		"since=1h&bucket_ms=86400001",
		"since=1m&bucket_ms=900000",
		"since=1h&bucket_ms=60000&group_by=uuid",
		"since=1h&bucket_ms=1000",
		"bucket_ms=60000",
	} {
		t.Run(query, func(t *testing.T) {
			store := &fakeReadableStore{
				HistogramFn: func(context.Context, *output.HistogramRequest) (*output.HistogramResult, error) {
					return &output.HistogramResult{}, nil
				},
			}
			srv := buildTestServerWithStore(t, store)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/histogram?"+query, http.NoBody)
			resp, err := srv.app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Nil(t, store.LastHistogramReq, "invalid request must not reach the store")
		})
	}
}

func TestHandleEventsHistogram_BackendFailure(t *testing.T) {
	store := &fakeReadableStore{
		HistogramFn: func(context.Context, *output.HistogramRequest) (*output.HistogramResult, error) {
			return nil, errors.New("store unavailable")
		},
	}
	srv := buildTestServerWithStore(t, store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/histogram?since=1h&bucket_ms=60000", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHandleEventsHistogram_RouteNotShadowedByUUID(t *testing.T) {
	store := &fakeReadableStore{}
	srv := buildTestServerWithStore(t, store)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/histogram?since=1h&bucket_ms=900000", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.NotNil(t, store.LastHistogramReq, "must hit Histogram, not GetEvent('histogram')")
	assert.Empty(t, store.LastGetEventUUID)
}
