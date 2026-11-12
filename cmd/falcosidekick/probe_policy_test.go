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

package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/outputs/loki"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/reload"
)

// lokiDestination is a Loki that answers ready and push only while up, on the path it was given.
type lokiDestination struct {
	server *httptest.Server
	up     atomic.Bool
	pushes atomic.Int32
	hits   atomic.Int32
}

func newLokiDestination(t *testing.T, tlsServer bool, status int) *lokiDestination {
	t.Helper()
	d := &lokiDestination{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.hits.Add(1)
		if !d.up.Load() {
			w.WriteHeader(status)
			return
		}
		if r.URL.Path == "/loki/api/v1/push" {
			d.pushes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	if tlsServer {
		d.server = httptest.NewTLSServer(handler)
	} else {
		d.server = httptest.NewServer(handler)
	}
	t.Cleanup(d.server.Close)
	return d
}

func closedPort(t *testing.T) string {
	t.Helper()
	l, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return "http://" + addr
}

// probeCase is one entry of the probe policy matrix; dest is nil for a local error and an unreachable destination.
type probeCase struct {
	dest    *lokiDestination
	cfg     map[string]any
	name    string
	warning string
	local   bool
}

func probeCases(t *testing.T) []probeCase {
	t.Helper()
	missing := newLokiDestination(t, false, http.StatusNotFound)
	denied := newLokiDestination(t, false, http.StatusUnauthorized)
	untrusted := newLokiDestination(t, true, http.StatusOK)
	untrusted.up.Store(true)
	return []probeCase{
		{name: "local invalid", cfg: map[string]any{"host": "not a url"}, local: true},
		{name: "remote unreachable", cfg: map[string]any{"host": closedPort(t)}, warning: "connection refused"},
		{name: "remote missing resource", cfg: map[string]any{"host": missing.server.URL}, dest: missing, warning: "HTTP 404"},
		{name: "remote auth rejected", cfg: map[string]any{"host": denied.server.URL}, dest: denied, warning: "HTTP 401"},
		{name: "remote TLS rejected", cfg: map[string]any{"host": untrusted.server.URL}, dest: untrusted, warning: "certificate"},
	}
}

func probeCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.New([]output.Type{loki.OutputType, webhook.OutputType})
	require.NoError(t, err)
	return cat
}

// checkApplied asserts the output runs degraded and that a TLS failure never fell back to plain HTTP.
func checkApplied(t *testing.T, tc *probeCase, status *pipeline.OutputStatus) {
	t.Helper()
	assert.Equal(t, pipeline.HealthDegraded, status.Status)
	assert.Equal(t, pipeline.WarningDestination, status.WarningKind)
	assert.Contains(t, status.LastWarning, "health check failed before start")
	assert.Contains(t, status.LastWarning, tc.warning)
	if tc.name == "remote TLS rejected" {
		assert.Zero(t, tc.dest.hits.Load(), "verification refuses the connection; there is no fallback")
	}
}

func lokiStatus(t *testing.T, d *pipeline.Dispatcher) *pipeline.OutputStatus {
	t.Helper()
	statuses := d.CollectStatus()
	for i := range statuses {
		if statuses[i].Name == "loki" {
			return &statuses[i]
		}
	}
	t.Fatal("no status for loki")
	return nil
}

// A locally invalid configuration is refused; a valid one whose destination fails its probe runs degraded.
func TestProbePolicyMatrix(t *testing.T) {
	ctx := context.Background()
	cfg := loadDefaultConfigForCmdTest(t)
	cat := probeCatalog(t)
	mc := metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000})

	t.Run("startup", func(t *testing.T) {
		for _, tc := range probeCases(t) {
			t.Run(tc.name, func(t *testing.T) {
				outs, err := createOutputs(ctx, cfg, map[string]map[string]any{"loki": tc.cfg}, cat, mc)
				if tc.local {
					require.ErrorContains(t, err, "host", "startup stops before serving")
					return
				}
				require.NoError(t, err)
				t.Cleanup(func() { closeOutputs(outs) })
				status := outs[0].GetStatus()
				checkApplied(t, &tc, &status)
			})
		}
	})

	t.Run("restore", func(t *testing.T) {
		for _, tc := range probeCases(t) {
			t.Run(tc.name, func(t *testing.T) {
				db := database.NewMemory()
				_, err := db.SaveOutputConfig(ctx, "loki", 0, tc.cfg)
				require.NoError(t, err)
				restored, err := restoreFromDB(ctx, cfg, db, cat, mc, nil)
				require.NoError(t, err)
				if tc.local {
					assert.Empty(t, restored.outputs)
					assert.ErrorContains(t, restored.failures["loki"], "host", "the stored output starts failed")
					return
				}
				require.Len(t, restored.outputs, 1)
				t.Cleanup(func() { closeOutputs(restored.outputs) })
				assert.Empty(t, restored.failures)
				status := restored.outputs[0].GetStatus()
				checkApplied(t, &tc, &status)
			})
		}
	})

	t.Run("API", func(t *testing.T) {
		for _, tc := range probeCases(t) {
			t.Run(tc.name, func(t *testing.T) {
				db := database.NewMemory()
				r, d := newProbeReloader(t, cat, db, nil)
				version, err := r.ApplyOutput(ctx, "loki", 0, tc.cfg)
				stored, getErr := db.GetOutputConfig(ctx, "loki")
				require.NoError(t, getErr)
				if tc.local {
					require.ErrorIs(t, err, pipeline.ErrInvalidOutputConfig, "the API answers 400")
					assert.Nil(t, stored, "nothing is saved")
					assert.Empty(t, d.CollectStatus())
					return
				}
				require.NoError(t, err)
				assert.Equal(t, int64(1), version)
				require.NotNil(t, stored, "the change is saved")
				checkApplied(t, &tc, lokiStatus(t, d))
			})
		}
	})

	t.Run("reload", func(t *testing.T) {
		for _, tc := range probeCases(t) {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "outputs.yaml")
				require.NoError(t, os.WriteFile(path, []byte("outputs: {}\n"), 0o600))
				r, d := newProbeReloader(t, cat, nil, []string{path})
				body := "outputs:\n  loki:\n    host: " + quoteYAML(tc.cfg["host"].(string)) + "\n"
				require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
				_, err := r.ReconcileFiles(ctx, t.Context(), time.Second, reload.TriggerForce)
				if tc.local {
					require.Error(t, err, "the reload is rejected")
					assert.Empty(t, d.CollectStatus(), "the active outputs are kept")
					return
				}
				require.NoError(t, err)
				checkApplied(t, &tc, lokiStatus(t, d))
			})
		}
	})
}

func quoteYAML(s string) string { return `"` + s + `"` }

func newProbeReloader(t *testing.T, cat *catalog.Catalog, db core.Database, paths []string) (*reload.Reloader, *pipeline.Dispatcher) {
	t.Helper()
	d := pipeline.NewDispatcher(nil)
	workerCtx, stop := context.WithCancel(context.Background())
	d.Start(workerCtx)
	t.Cleanup(func() { _ = d.Shutdown(context.Background(), stop) })
	r := reload.NewReloader(&reload.ReloaderConfig{
		OutputPaths: paths, Catalog: cat, Dispatcher: d, Database: db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.New(slog.DiscardHandler)},
		Logger: slog.New(slog.DiscardHandler), InitialOutputs: map[string]map[string]any{},
	})
	r.BindWorkerContext(workerCtx, time.Second)
	t.Cleanup(r.Close)
	return r, d
}

func TestDegradedOutputRecoversWithoutRestart(t *testing.T) {
	ctx := context.Background()
	cfg := loadDefaultConfigForCmdTest(t)
	dest := newLokiDestination(t, false, http.StatusServiceUnavailable)
	var siblingPosts atomic.Int32
	sibling := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		siblingPosts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sibling.Close)

	outs, err := createOutputs(ctx, cfg, map[string]map[string]any{
		"loki":    {"host": dest.server.URL, "runtime": map[string]any{"retry": map[string]any{"max_attempts": 1}}},
		"webhook": {"host": sibling.URL},
	}, probeCatalog(t), metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}))
	require.NoError(t, err)
	d := pipeline.NewDispatcher(outs)
	workerCtx, stop := context.WithCancel(ctx)
	d.Start(workerCtx)
	t.Cleanup(func() { _ = d.Shutdown(context.Background(), stop) })
	require.Equal(t, pipeline.HealthDegraded, lokiStatus(t, d).Status)

	d.DispatchEvent(testutil.CreateValidEvent())
	require.Eventually(t, func() bool { return siblingPosts.Load() == 1 }, 5*time.Second, 10*time.Millisecond,
		"the sibling delivers while the destination is down")

	dest.up.Store(true)
	d.DispatchEvent(testutil.CreateValidEvent())
	require.Eventually(t, func() bool { return dest.pushes.Load() >= 1 }, 10*time.Second, 10*time.Millisecond,
		"the recovered destination delivers without a restart")
	require.Eventually(t, func() bool { return lokiStatus(t, d).LastWarning == "" }, 5*time.Second, 10*time.Millisecond)
}
