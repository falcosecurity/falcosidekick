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
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
	"github.com/falcosecurity/falcosidekick/internal/outputs/inmemory"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

// The UI tests consume these fixtures, so every shape the UI reads comes from the real handlers.
// Run `go test ./internal/api/ -run TestUIContractFixtures -update` after a contract change.
var updateUIFixtures = flag.Bool("update", false, "rewrite the UI contract fixtures under ui/src/test/fixtures")

const (
	uiFixtureDir = "../../ui/src/test/fixtures"
	uiUUIDKey    = "uuid"
)

var uiFixtureClock = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

type uiFixtureCase struct {
	name string
	path string
}

type uiErrorFixture struct {
	Body   any `json:"body"`
	Status int `json:"status"`
}

func TestUIContractFixtures(t *testing.T) {
	ctx := t.Context()
	db := database.NewMemory()
	require.NoError(t, db.Provision(ctx, &core.ProvisionRequest{Outputs: map[string]map[string]any{
		"inmemory": {"capacity": 5000},
	}}))
	_, err := db.SaveOutputConfig(ctx, "webhook", 0, map[string]any{
		"host":     "http://127.0.0.1:2899",
		"endpoint": "/events",
		"headers":  map[string]any{"X-Api-Key": map[string]any{"values": []any{"public"}, "secrets": []any{"s3cr3t"}}},
	})
	require.NoError(t, err)
	_, err = db.SaveOutputConfig(ctx, "alertmanager", 0, map[string]any{"hosts": []any{"http://127.0.0.1:2899"}})
	require.NoError(t, err)

	cat, err := catalog.New(all.Types())
	require.NoError(t, err)
	runtimeCfg := testutil.DefaultRuntimeConfig()
	store, err := inmemory.OutputType.New(map[string]any{"capacity": 5000}, output.Deps{Logger: slog.Default()})
	require.NoError(t, err)
	refused := &testutil.MockDriver{
		DriverName: "webhook",
		SendFunc:   func(context.Context, *event.Event) error { return errors.New("connection refused") },
	}
	dispatcher := pipeline.NewDispatcher([]*pipeline.Output{
		pipeline.NewOutput(store, &runtimeCfg, nil),
		pipeline.NewOutput(refused, &runtimeCfg, nil),
	})
	dispatcher.MarkFailed("alertmanager", "build output alertmanager: hosts: must be a valid URL")

	enricher, err := pipeline.NewEnricher(output.EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)
	workerCtx, stopWorkers := context.WithCancel(ctx)
	p.Start(workerCtx, stopWorkers)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(shutdownCtx)
	})

	cfg := testConfig(t)
	cfg.UI.EventSource = "inmemory"
	srv, err := NewServer(&ServerConfig{Pipeline: p, Database: db, Catalog: cat, Config: cfg, RuntimeDefaults: uiFixtureRuntimeDefaults()})
	require.NoError(t, err)

	layoutEmpty := uiFixtureRequest(t, srv.app, http.MethodGet, "/api/v1/pipeline/layout", "", http.StatusOK)
	require.NoError(t, db.SavePipelineLayout(ctx, &core.PipelineLayout{Nodes: []core.LayoutNode{
		{ID: "source:falco", X: 0, Y: 120},
		{ID: "core:sidekick", X: 320, Y: 120},
		{ID: "sink:inmemory", X: 640, Y: 0},
		{ID: "sink:webhook", X: 640, Y: 120.5},
		{ID: "sink:alertmanager", X: 640, Y: 240},
	}}))

	now := time.Now()
	for _, evt := range uiFixtureEvents(now) {
		body, err := json.Marshal(evt)
		require.NoError(t, err)
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res, err := srv.ingestion.Test(req)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		require.Equal(t, http.StatusOK, res.StatusCode)
	}
	readable, ok := store.(output.ReadableStore)
	require.True(t, ok)
	require.Eventually(t, func() bool {
		count, err := readable.Count(ctx, &output.Filters{})
		if err != nil || count != 3 {
			return false
		}
		return slices.ContainsFunc(p.CollectOutputStatus(), func(s pipeline.OutputStatus) bool {
			return s.Name == "webhook" && s.FailedTotal == 3
		})
	}, 5*time.Second, 10*time.Millisecond)

	search := uiFixtureRequest(t, srv.app, http.MethodGet, "/api/v1/events/search?limit=10", "", http.StatusOK)
	events, ok := search["events"].([]any)
	require.True(t, ok)
	require.Len(t, events, 3)
	newest, ok := events[0].(map[string]any)
	require.True(t, ok)
	firstUUID, ok := newest["uuid"].(string)
	require.True(t, ok)

	fixtures := map[string]any{
		"layout-empty":  layoutEmpty,
		"events-search": search,
	}
	for _, c := range []uiFixtureCase{
		{name: "version", path: "/api/v1/version"},
		{name: "config", path: "/api/v1/config"},
		{name: "pipeline", path: "/api/v1/pipeline"},
		{name: "pipeline-status", path: "/api/v1/pipeline/status"},
		{name: "outputs", path: "/api/v1/pipeline/outputs"},
		{name: "output", path: "/api/v1/pipeline/outputs/webhook"},
		{name: "output-types", path: "/api/v1/pipeline/outputs/types"},
		{name: "output-type", path: "/api/v1/pipeline/outputs/types/webhook"},
		{name: "layout", path: "/api/v1/pipeline/layout"},
		{name: "events-count", path: "/api/v1/events/count"},
		{name: "events-count-by-priority", path: "/api/v1/events/count/priority"},
		{name: "events-histogram", path: "/api/v1/events/histogram?since=6h&bucket_ms=3600000&group_by=source"},
		{name: "event", path: "/api/v1/events/" + firstUUID},
	} {
		fixtures[c.name] = uiFixtureRequest(t, srv.app, http.MethodGet, c.path, "", http.StatusOK)
	}
	fixtures["errors"] = uiErrorFixtures(t, srv, cat)
	fixtures["config-postgres"] = uiPostgresConfigFixture(t, p, db, cat, cfg)

	canonicalizeUIFixtures(fixtures, now)
	for name, body := range fixtures {
		t.Run(name, func(t *testing.T) {
			compareUIFixture(t, name, body)
		})
	}
}

// uiFixtureEvents returns the events Falco would post, newest first, all inside the last six hours.
func uiFixtureEvents(now time.Time) []map[string]any {
	return []map[string]any{
		{
			"output":   "Terminal shell in container (user=root container=nginx shell=bash)",
			"priority": "Critical",
			"rule":     "Terminal shell in container",
			"time":     now.Add(-30 * time.Minute).UTC().Format(time.RFC3339Nano),
			"output_fields": map[string]any{
				"container.name": "nginx", "proc.name": "bash", "user.name": "root", "proc.pid": 4242,
			},
			"source":   "syscall",
			"tags":     []string{"container", "shell", "mitre_execution"},
			"hostname": "node-1",
		},
		{
			"output":   "Read sensitive file untrusted (file=/etc/shadow)",
			"priority": "Warning",
			"rule":     "Read sensitive file untrusted",
			"time":     now.Add(-90 * time.Minute).UTC().Format(time.RFC3339Nano),
			"output_fields": map[string]any{
				"fd.name": "/etc/shadow", "proc.name": "cat", "user.name": "app",
			},
			"source":   "syscall",
			"tags":     []string{"filesystem", "mitre_credential_access"},
			"hostname": "node-2",
		},
		{
			"output":   "K8s secret read (user=system:serviceaccount:default:ci)",
			"priority": "Notice",
			"rule":     "K8s Secret Get Successfully",
			"time":     now.Add(-3 * time.Hour).UTC().Format(time.RFC3339Nano),
			"output_fields": map[string]any{
				"ka.user.name": "system:serviceaccount:default:ci", "ka.target.name": "db-credentials",
			},
			"source": "k8s_audit",
			"tags":   []string{"k8s"},
		},
	}
}

// uiFixtureRuntimeDefaults sets every runtime default, so the UI sees each field GET /api/v1/config serves.
func uiFixtureRuntimeDefaults() output.RuntimeConfig {
	defaults := testutil.DefaultRuntimeConfig()
	defaults.MinPriority = event.PriorityWarning
	defaults.Batching = &output.BatchingConfig{Enabled: true, BatchSize: 50, FlushInterval: time.Second}
	healthCheck := true
	defaults.HealthCheck = &healthCheck
	return defaults
}

// uiErrorFixtures collects the error envelopes the UI maps to messages, keyed by case.
// uiPostgresConfigFixture serves a postgres configuration with an inline password and TLS files, so
// the UI sees the masked password and every database field the Configuration page shows.
func uiPostgresConfigFixture(
	t *testing.T, p *pipeline.Pipeline, db core.Database, cat *catalog.Catalog, base *core.Config,
) map[string]any {
	t.Helper()
	cfg := base.DeepCopy()
	cfg.Database.Backend = core.DatabasePostgres
	cfg.Database.Postgres.Host = "postgres.falco.svc"
	cfg.Database.Postgres.Database = "falcosidekick"
	cfg.Database.Postgres.User = "sidekick"
	cfg.Database.Postgres.Password = "not-a-real-password"
	cfg.Database.Postgres.TLS.CAFile = "/etc/falcosidekick/secrets/postgres-tls/ca.crt"
	cfg.API.AllowWrites = true
	cfg.API.SecretDirs = []string{"/etc/falcosidekick/secrets"}
	cfg.Metrics.ExtraLabels = []string{"cluster"}
	cfg.TLS = &core.TLSConfig{
		Enabled:  true,
		CertFile: "/etc/falcosidekick/certs/tls.crt",
		KeyFile:  "/etc/falcosidekick/certs/tls.key",
	}
	srv, err := NewServer(&ServerConfig{Pipeline: p, Database: db, Catalog: cat, Config: cfg, RuntimeDefaults: uiFixtureRuntimeDefaults()})
	require.NoError(t, err)
	body := uiFixtureRequest(t, srv.app, http.MethodGet, "/api/v1/config", "", http.StatusOK)
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "not-a-real-password")
	return body
}

func uiErrorFixtures(t *testing.T, srv *Server, cat *catalog.Catalog) map[string]uiErrorFixture {
	t.Helper()
	cases := map[string]uiErrorFixture{
		"not_found": {
			Status: http.StatusNotFound,
			Body:   uiFixtureRequest(t, srv.app, http.MethodGet, "/api/v1/events/missing", "", http.StatusNotFound),
		},
		"bad_request": {
			Status: http.StatusBadRequest,
			Body:   uiFixtureRequest(t, srv.app, http.MethodGet, "/api/v1/events/search?since=soon", "", http.StatusBadRequest),
		},
		"writes_disabled": {
			Status: http.StatusForbidden,
			Body: uiFixtureRequest(t, srv.app, http.MethodPut, "/api/v1/pipeline/outputs/webhook",
				`{"config":{},"version":2}`, http.StatusForbidden),
		},
	}

	noDatabase := buildTestServer(t, nil)
	cases["database_not_configured"] = uiErrorFixture{
		Status: http.StatusServiceUnavailable,
		Body:   uiFixtureRequest(t, noDatabase.app, http.MethodGet, "/api/v1/pipeline", "", http.StatusServiceUnavailable),
	}
	cases["event_store_unavailable"] = uiErrorFixture{
		Status: http.StatusServiceUnavailable,
		Body:   uiFixtureRequest(t, noDatabase.app, http.MethodGet, "/api/v1/events/search", "", http.StatusServiceUnavailable),
	}

	writableDB := database.NewMemory()
	seedOutput(t, writableDB, "webhook", map[string]any{"host": "http://127.0.0.1:2899"})
	writable := buildMutationRig(t, writableDB, cat, true).Server
	cases["version_conflict"] = uiErrorFixture{
		Status: http.StatusConflict,
		Body: uiFixtureRequest(t, writable.app, http.MethodPut, "/api/v1/pipeline/outputs/webhook",
			`{"config":{"endpoint":"/v2/events"},"version":99}`, http.StatusConflict),
	}
	cases["validation"] = uiErrorFixture{
		Status: http.StatusBadRequest,
		Body: uiFixtureRequest(t, writable.app, http.MethodPut, "/api/v1/pipeline/outputs/slack",
			`{"config":{"channel":"#alerts"},"version":0}`, http.StatusBadRequest),
	}
	return cases
}

func uiFixtureRequest(t *testing.T, app *fiber.App, method, path, body string, wantStatus int) map[string]any {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := app.Test(req)
	require.NoError(t, err)
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.Equal(t, wantStatus, res.StatusCode, "%s %s: %s", method, path, raw)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded), "%s %s: %s", method, path, raw)
	return decoded
}

// canonicalizeUIFixtures replaces what changes between runs while keeping every shape and relation:
// times move to the fixture clock at their offset from now, to the minute (events keep their spacing,
// times taken during the run land on the clock itself), histogram instants keep their spacing, UUIDs
// stay distinct and lists of named entries are sorted by name. Nothing depends on how many distinct
// instants a run happened to produce.
func canonicalizeUIFixtures(fixtures map[string]any, now time.Time) {
	var epochs []float64
	uuids := map[string]string{}
	walkUIFixture(fixtures, "", func(key string, value any) any {
		switch v := value.(type) {
		case string:
			if key == uiUUIDKey {
				if _, seen := uuids[v]; !seen {
					uuids[v] = fmt.Sprintf("00000000-0000-4000-8000-%012d", len(uuids)+1)
				}
			}
		case float64:
			if isUIEpochKey(key) {
				epochs = append(epochs, v)
			}
		}
		return value
	})
	epochBase := float64(uiFixtureClock.Add(-6 * time.Hour).UnixMilli())
	epochMin := epochBase
	if len(epochs) > 0 {
		epochMin = slices.Min(epochs)
	}

	fixtures["version"] = map[string]any{
		"version": "3.0.0-beta.1", "commit": "0123456789abcdef0123456789abcdef01234567",
		"build_date": uiFixtureClock.Format(time.RFC3339), "go_version": "go1.26.0",
	}
	for name, body := range fixtures {
		fixtures[name] = walkUIFixture(body, "", func(key string, value any) any {
			switch v := value.(type) {
			case string:
				if isUITimeKey(key) {
					if ts, err := time.Parse(time.RFC3339Nano, v); err == nil && !ts.IsZero() {
						return uiFixtureClock.Add(ts.Sub(now).Round(time.Minute)).Format(time.RFC3339Nano)
					}
				}
				if key == uiUUIDKey {
					return uuids[v]
				}
			case float64:
				if isUIEpochKey(key) {
					return epochBase + (v - epochMin)
				}
			}
			return value
		})
	}
}

func isUITimeKey(key string) bool {
	return key == "time" || key == "last_success" || key == "updated_at"
}

func isUIEpochKey(key string) bool {
	return key == "t" || key == "from" || key == "to"
}

// walkUIFixture applies visit to every leaf, passing the key it sits under, and sorts the lists the
// server builds from maps by name; schema fields keep the order the catalog declares.
func walkUIFixture(value any, key string, visit func(key string, value any) any) any {
	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			v[k] = walkUIFixture(child, k, visit)
		}
		return v
	case map[string]uiErrorFixture:
		out := make(map[string]any, len(v))
		for k, child := range v {
			out[k] = map[string]any{"status": child.Status, "body": walkUIFixture(child.Body, "body", visit)}
		}
		return out
	case []any:
		for i, child := range v {
			v[i] = walkUIFixture(child, key, visit)
		}
		if key == "status" || key == "outputs" || key == "types" {
			slices.SortStableFunc(v, func(a, b any) int {
				return strings.Compare(uiFixtureName(a), uiFixtureName(b))
			})
		}
		return v
	default:
		return visit(key, value)
	}
}

func uiFixtureName(value any) string {
	object, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	name, _ := object["name"].(string)
	return name
}

func compareUIFixture(t *testing.T, name string, body any) {
	t.Helper()
	actual, err := json.MarshalIndent(body, "", "  ")
	require.NoError(t, err)
	actual = append(actual, '\n')
	path := filepath.Join(uiFixtureDir, name+".json")
	if *updateUIFixtures {
		require.NoError(t, os.MkdirAll(uiFixtureDir, 0o750))
		require.NoError(t, os.WriteFile(path, actual, 0o600))
	}
	expected, err := os.ReadFile(path)
	require.NoError(t, err, "missing fixture %s: run with -update", path)
	assert.JSONEq(t, string(expected), string(actual), "fixture %s is stale: run with -update", path)
}
