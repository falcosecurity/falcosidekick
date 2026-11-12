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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/outputs/kafka"
	"github.com/falcosecurity/falcosidekick/internal/outputs/otlp"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// canary is submitted in every refused value: no error message may quote it.
const canary = "c4nary-value"

// No error message quotes the submitted value, and nothing is saved.
func TestPUTValidationErrorShape(t *testing.T) {
	secrets := t.TempDir()
	ca := secrets + "/ca.pem"
	require.NoError(t, os.WriteFile(ca, []byte("not a certificate "+canary), 0o600))
	cat, err := catalog.New([]output.Type{webhook.OutputType, kafka.OutputType, otlp.OutputType})
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		output string
		config string
		phase  string
		fields []fieldError
	}{
		{
			name: "range", output: "webhook", phase: "validate",
			config: `{"host":"http://h","runtime":{"workers":1000}}`,
			fields: []fieldError{{Path: "runtime.workers", Message: "must be an integer between 1 and 256"}},
		},
		{
			name: "type", output: "webhook", phase: "validate",
			config: `{"host":"http://h","runtime":{"queue_size":"` + canary + `"}}`,
			fields: []fieldError{{Path: "runtime.queue_size", Message: "must be an integer"}},
		},
		{
			name: "duration", output: "webhook", phase: "validate",
			config: `{"host":"http://h","runtime":{"retry":{"initial_interval":"` + canary + `"}}}`,
			fields: []fieldError{{Path: "runtime.retry.initial_interval", Message: "must be a duration such as 30s or 1m"}},
		},
		{
			name: "nested runtime merge", output: "webhook", phase: "validate",
			config: `{"host":"http://h","runtime":{"workers":256,"batching":{"enabled":true,"batch_size":10000,"flush_interval":"1s"}}}`,
			fields: []fieldError{{Path: "runtime.batching.batch_size", Message: "must be at most 390 with 256 workers: workers × batch_size is limited to 100000"}},
		},
		{
			name: "driver field", output: "kafka", phase: "validate",
			config: `{"brokers":["b:9092"],"topic":"t","auth":{"username":"` + canary + `"}}`,
			fields: []fieldError{{Path: "auth.sasl", Message: "is required when username or password is set"}},
		},
		{
			name: "otlp configuration-level error has no empty field", output: "otlp", phase: "validate",
			config: `{}`,
		},
		{
			name: "otlp bad CA is a field error at create", output: "otlp", phase: "validate",
			config: `{"logs":{"endpoint":"https://c:4318","tls":{"ca_file":"` + ca + `"}}}`,
			fields: []fieldError{{Path: "logs.tls.ca_file", Message: "no valid PEM certificate"}},
		},
		{
			name: "otlp metrics-only bad CA is a field error at create", output: "otlp", phase: "validate",
			config: `{"metrics":{"endpoint":"https://c:4318","tls":{"ca_file":"` + ca + `"}}}`,
			fields: []fieldError{{Path: "metrics.tls.ca_file", Message: "no valid PEM certificate"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := database.NewMemory()
			rig := buildMutationRig(t, db, cat, true)
			rig.Server.secretDirs = []string{secrets}
			status, body := putOutput(t, rig, tc.output, `{"version":0,"config":`+tc.config+`}`)
			require.Equal(t, http.StatusBadRequest, status, body)
			assert.NotContains(t, body, canary, "no submitted value in the answer")
			var got errorResponse
			require.NoError(t, json.Unmarshal([]byte(body), &got))
			assert.Equal(t, tc.phase, got.Phase)
			assert.NotEmpty(t, got.Error)
			if tc.fields == nil {
				assert.Empty(t, got.Fields)
				assert.NotContains(t, got.Error, ": :", "no empty field name")
			} else {
				assert.Equal(t, tc.fields, got.Fields)
			}
			stored, err := db.GetOutputConfig(t.Context(), tc.output)
			require.NoError(t, err)
			assert.Nil(t, stored, "nothing is saved")
		})
	}
}

func TestFieldErrors(t *testing.T) {
	errs := utils.ValidationErrors{{Field: "a", Message: "x"}, {Message: "whole config"}}
	joined := errors.Join(fmt.Errorf("one: %w", errs), utils.ValidationError{Field: "b", Message: "y"})
	assert.Equal(t, []fieldError{{Path: "a", Message: "x"}, {Path: "b", Message: "y"}}, fieldErrors(joined))
	assert.Nil(t, fieldErrors(errors.New("plain")))
	assert.Nil(t, fieldErrors(nil))
}

func TestErrorHandlerHidesPanics(t *testing.T) {
	srv := buildTestServer(t, nil)
	srv.app.Get("/api/v1/boom", func(fiber.Ctx) error { panic("makechan: " + canary) })
	srv.ingestion.Get("/boom", func(fiber.Ctx) error { return errors.New("internal " + canary) })
	for _, tc := range []struct {
		app  *fiber.App
		name string
		path string
	}{
		{name: "management panic", app: srv.app, path: "/api/v1/boom"},
		{name: "ingestion error", app: srv.ingestion, path: "/boom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, http.NoBody))
			require.NoError(t, err)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
			assert.JSONEq(t, `{"error":"internal error; see the falcosidekick log"}`, string(body))
		})
	}

	resp, err := srv.app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/"+canary, http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.JSONEq(t, `{"error":"Not Found"}`, string(body), "a Fiber error answers its status text, not the path")
}

// Counted once; an oversized management request is not counted.
func TestOversizedIngestIsCountedInvalid(t *testing.T) {
	collector := metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000})
	enricher, err := pipeline.NewEnricher(output.EnricherConfig{})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), collector)
	require.NoError(t, err)
	cfg := testConfig(t)
	cfg.ListenPort, cfg.Management.ListenPort = freePort(t), freePort(t)
	srv, err := NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t), Metrics: collector,
		Registry: collector.Registry(), Config: cfg})
	require.NoError(t, err)
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ingest := fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort)
	management := fmt.Sprintf("http://127.0.0.1:%d", cfg.Management.ListenPort)
	waitFor(t, func() bool {
		resp, err := http.Get(ingest + routeLive) //nolint:noctx // test probe
		if err == nil {
			_ = resp.Body.Close()
		}
		return err == nil
	})

	// The server may reset the connection while the client still sends: then there is no status.
	post := func(url string, size int) int {
		body := `{"rule":"` + strings.Repeat("x", size) + `"}`
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	assert.Contains(t, []int{0, http.StatusRequestEntityTooLarge}, post(ingest+"/", maxBodySize))
	assert.Contains(t, []int{0, http.StatusRequestEntityTooLarge}, post(management+"/api/v1/pipeline/layout", maxBodySize))
	assert.Equal(t, http.StatusBadRequest, post(ingest+"/", maxBodySize-64), "just under the limit reaches the handler")

	waitFor(t, func() bool {
		resp, err := http.Get(ingest + routeMetrics) //nolint:noctx // test probe
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		metricsBody, _ := io.ReadAll(resp.Body)
		// The oversized post and the invalid one; not the management request.
		return strings.Contains(string(metricsBody), `falcosidekick_ingest_requests_total{status="invalid"} 2`+"\n")
	})
}

// The 413 answer of the error handler, through the same path fasthttp takes for an oversized body.
func TestErrorHandlerAnswers413(t *testing.T) {
	srv := buildTestServer(t, nil)
	srv.ingestion.Post("/too-large", func(fiber.Ctx) error { return fiber.ErrRequestEntityTooLarge })
	resp, err := srv.ingestion.Test(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/too-large", http.NoBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	assert.JSONEq(t, `{"error":"Request Entity Too Large"}`, string(body))
}
