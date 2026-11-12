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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	databasetestutil "github.com/falcosecurity/falcosidekick/internal/database/testutil"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

func createValidEventJSON() []byte {
	evt := event.Event{
		Time:         time.Now().UTC(),
		OutputFields: map[string]interface{}{"proc.name": "bash"},
		Tags:         []string{"test"},
		Rule:         "Test rule",
		Output:       "test output",
		Source:       "syscall",
		Hostname:     "node-1",
		Priority:     event.PriorityWarning,
	}
	data, _ := json.Marshal(evt)
	return data
}

func TestHandlePostEventValid(t *testing.T) {
	var received atomic.Int64
	cfg := testutil.DefaultRuntimeConfig()
	cfg.MinPriority = event.PriorityDebug
	out := pipeline.NewOutput(&testutil.MockDriver{DriverName: "test", SendFunc: func(_ context.Context, _ *event.Event) error {
		received.Add(1)
		return nil
	}}, &cfg, nil)

	srv := buildTestServer(t, []*pipeline.Output{out})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(createValidEventJSON()))
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.ingestion.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int64(1), received.Load())
}

func TestHandlePostEventInvalidJSON(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader([]byte(`{invalid`)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.ingestion.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 400, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "error")
}

func TestHandlePostEventMissingRule(t *testing.T) {
	srv := buildTestServer(t, nil)

	evt := map[string]interface{}{
		"time":   time.Now().UTC(),
		"source": "syscall",
	}
	data, _ := json.Marshal(evt)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.ingestion.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 400, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "rule is required")
}

// /livez answers while the process serves; /readyz follows SetReady: not ready until the pipeline
// runs, ready, then not ready again from SIGTERM on.
func TestLivenessAndReadiness(t *testing.T) {
	srv := buildTestServer(t, nil)
	get := func(path string) (int, string) {
		resp, err := srv.ingestion.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody))
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	status, body := get("/livez")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"status":"ok"}`, body)

	status, body = get("/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, status, "not ready before the pipeline runs")
	assert.JSONEq(t, `{"status":"not ready"}`, body)

	srv.SetReady(true)
	status, body = get("/readyz")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"status":"ready"}`, body)

	srv.SetReady(false)
	status, _ = get("/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, status, "not ready while draining")
	status, _ = get("/livez")
	assert.Equal(t, http.StatusOK, status, "still alive while draining")
}

func TestHandleGetVersion(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/version", http.NoBody)

	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "version")
}

func TestServerDefaults(t *testing.T) {
	enricher, err := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)

	srv, err := NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t), Config: testConfig(t)})
	require.NoError(t, err)
	assert.Equal(t, ":2801", srv.address, "ingestion listens on every interface, IPv4 and IPv6")
	assert.Equal(t, "127.0.0.1:2802", srv.managementAddress, "the unauthenticated API stays local")

	_, err = NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t)})
	assert.EqualError(t, err, "server: config is required")
}

func TestNewServerRejectsNilPipeline(t *testing.T) {
	_, err := NewServer(&ServerConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pipeline is required")
}

func TestNewServerRejectsNilCatalog(t *testing.T) {
	enricher, err := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)

	_, err = NewServer(&ServerConfig{Pipeline: p})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "catalog is required")
}

// The configuration comes from this replica's files, never from the database.
func TestHandleGetConfigServesThisReplicaConfiguration(t *testing.T) {
	cfg := testConfig(t)
	cfg.ListenPort = 2999
	for name, db := range map[string]core.Database{"no database": nil, "failing database": allReadsFailDB()} {
		t.Run(name, func(t *testing.T) {
			enricher, err := pipeline.NewEnricher(output.EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
			require.NoError(t, err)
			p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
			require.NoError(t, err)
			defaults := testutil.DefaultRuntimeConfig()
			defaults.Workers = 4
			defaults.QueueSize = 2048
			defaults.MinPriority = event.PriorityWarning
			srv, err := NewServer(&ServerConfig{
				Pipeline: p, Database: db, Catalog: newTestCatalog(t), Config: cfg, RuntimeDefaults: defaults,
			})
			require.NoError(t, err)
			cfg.ListenPort = 1 // the server keeps its own copy
			defaults.Retry.MaxAttempts = 99

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/config", http.NoBody)
			resp, err := srv.app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			var got struct {
				Config map[string]any `json:"config"`
			}
			require.NoError(t, json.Unmarshal(body, &got))
			assert.InDelta(t, 2999, got.Config["listen_port"], 0)
			assert.Equal(t, "5s", got.Config["shutdown_delay"], "durations are Go duration strings")
			database, _ := got.Config["database"].(map[string]any)
			assert.Equal(t, "inmemory", database["backend"])
			assert.Equal(t, "30s", database["connect_timeout"])
			assert.Equal(t, map[string]any{"poll_interval": "30s", "retire_timeout": "10s"}, got.Config["reload"])

			assert.Equal(t, map[string]any{
				"minimum_priority": "Warning",
				"queue_size":       float64(2048),
				"workers":          float64(4),
				"retry": map[string]any{
					"initial_interval": "10ms", "max_interval": "100ms", "max_attempts": float64(1), "multiplier": float64(2),
				},
				"circuit_breaker": map[string]any{
					"reset_timeout": "30s", "failure_threshold": float64(5), "success_threshold": float64(2),
				},
			}, got.Config["runtime_defaults"], "the server keeps its own copy of the runtime defaults")
			cfg.ListenPort = 2999
		})
	}
}

func TestLegacyOutputsPathIsRemoved(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 404, resp.StatusCode, "legacy /api/v1/outputs must be removed; callers use /api/v1/pipeline/outputs")
}

func TestStartAndShutdown(t *testing.T) {
	srv := buildTestServer(t, nil)

	started := make(chan struct{})
	go func() {
		close(started)
		_ = srv.Start()
	}()
	<-started

	time.Sleep(50 * time.Millisecond)
	require.NoError(t, srv.Shutdown(t.Context()))
}

// A sender posting something that is not a Falco event shows in ingest_requests_total{status="invalid"}:
// a malformed body and an event that fails validation both count, and neither reaches the pipeline.
func TestInvalidPostsAreCounted(t *testing.T) {
	collector := metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000})
	enricher, err := pipeline.NewEnricher(output.EnricherConfig{})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), collector)
	require.NoError(t, err)
	srv, err := NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t), Metrics: collector,
		Registry: collector.Registry(), Config: testConfig(t)})
	require.NoError(t, err)

	post := func(body string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.ingestion.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp.StatusCode
	}
	assert.Equal(t, http.StatusBadRequest, post(`{bad`), "malformed JSON")
	assert.Equal(t, http.StatusBadRequest, post(`{"priority":"Warning","time":"2026-01-01T00:00:00Z"}`), "no rule")
	assert.Equal(t, http.StatusOK, post(string(createValidEventJSON())))

	resp, err := srv.ingestion.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `falcosidekick_ingest_requests_total{status="invalid"} 2`)
	assert.Contains(t, string(body), `falcosidekick_ingest_requests_total{status="accepted"} 1`)
	assert.Equal(t, 1, strings.Count(string(body), "\nfalcosidekick_events_total{"), "only the valid post reaches the pipeline")
}

func TestHandlePostEventWithMetrics(t *testing.T) {
	collector := metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000})
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher(nil)
	p, err := pipeline.NewPipeline(enricher, dispatcher, collector)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})

	srv, err := NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t), Metrics: collector, Config: testConfig(t)})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(createValidEventJSON()))
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.ingestion.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
}

func TestNewServerWithMetricsRegistry(t *testing.T) {
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	srv, err := NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t), Registry: reg, Config: testConfig(t)})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody)
	resp, err := srv.ingestion.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
}

func allReadsFailDB() *databasetestutil.Mock {
	err := errors.New("db failure")
	return &databasetestutil.Mock{
		GetOutputConfigsErr: err,
		GetOutputConfigErr:  err,
	}
}

func TestHandleGetOutputsDBError(t *testing.T) {
	srv := buildTestServerWithDB(t, allReadsFailDB())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 503, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), "db failure", "database text stays out of the answer")
}

func TestGetReadableStoreReturnsNilWhenNoEventSource(t *testing.T) {
	srv := buildTestServer(t, nil)
	assert.Nil(t, srv.GetReadableStore())
}

func TestGetReadableStoreResolvesFromPipeline(t *testing.T) {
	store := &fakeReadableStore{MockDriver: testutil.MockDriver{DriverName: "inmemory"}}
	cfg := testutil.DefaultRuntimeConfig()
	out := pipeline.NewOutput(store, &cfg, nil)

	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher([]*pipeline.Output{out})
	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})

	srv, err := NewServer(
		&ServerConfig{
			Pipeline: p,
			Catalog:  newTestCatalog(t),
			Config: &core.Config{
				UI: core.UIConfig{
					EventSource: "inmemory",
				},
			},
		},
	)
	require.NoError(t, err)

	rs := srv.GetReadableStore()
	assert.NotNil(t, rs, "must resolve ReadableStore from pipeline")
}

func TestGetReadableStoreReturnsNilForNonReadableOutput(t *testing.T) {
	cfg := testutil.DefaultRuntimeConfig()
	out := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &cfg, nil)

	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher([]*pipeline.Output{out})
	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})

	srv, err := NewServer(
		&ServerConfig{
			Pipeline: p,
			Catalog:  newTestCatalog(t),
			Config: &core.Config{
				UI: core.UIConfig{
					EventSource: "slack",
				},
			},
		},
	)
	require.NoError(t, err)

	assert.Nil(t, srv.GetReadableStore(), "non-ReadableStore output must return nil")
}
