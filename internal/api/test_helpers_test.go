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
	"io/fs"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/reload"
)

const testEventSourceName = "inmemory"

// testConfig returns the core configuration a deployment without a core file starts from.
func testConfig(t *testing.T) *core.Config {
	t.Helper()
	cfg, err := config.Load("")
	require.NoError(t, err)
	return &cfg.Config
}

func newTestCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.New([]output.Type{{
		Name:   "noop",
		Schema: output.Schema{},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "noop"}, nil
		},
	}})
	require.NoError(t, err)
	return cat
}

func buildTestServer(t *testing.T, outputs []*pipeline.Output) *Server {
	t.Helper()
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher(outputs)

	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	if err != nil {
		t.Fatalf("build pipeline: %v", err)
	}

	p.Start(context.Background(), func() {})

	srv, err := NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t), Logger: slog.Default(), Config: testConfig(t)})
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	return srv
}

func buildTestServerWithDB(t *testing.T, db core.Database) *Server {
	t.Helper()
	return buildTestServerWithDBAndCatalog(t, db, newTestCatalog(t))
}

func buildTestServerWithDBAndCatalog(t *testing.T, db core.Database, cat *catalog.Catalog) *Server {
	t.Helper()
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher(nil)
	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})

	srv, err := NewServer(&ServerConfig{Pipeline: p, Database: db, Catalog: cat, Config: testConfig(t)})
	require.NoError(t, err)
	return srv
}

type fakeReadableStore struct {
	testutil.MockDriver
	SearchFn    func(ctx context.Context, q *output.SearchQuery) (*output.SearchResult, error)
	CountFn     func(ctx context.Context, f *output.Filters) (int64, error)
	CountByFn   func(ctx context.Context, field string, f *output.Filters) (map[string]int64, error)
	HistogramFn func(ctx context.Context, req *output.HistogramRequest) (*output.HistogramResult, error)
	GetEventFn  func(ctx context.Context, uuid string) (*event.Event, error)

	LastSearchQuery  *output.SearchQuery
	LastCountFilters *output.Filters
	LastCountByField string
	LastHistogramReq *output.HistogramRequest
	LastGetEventUUID string
	SearchCalls      atomic.Int32
}

func (f *fakeReadableStore) Search(ctx context.Context, q *output.SearchQuery) (*output.SearchResult, error) {
	f.SearchCalls.Add(1)
	f.LastSearchQuery = q
	if f.SearchFn != nil {
		return f.SearchFn(ctx, q)
	}
	return &output.SearchResult{Events: []event.Event{}, Page: q.Page, Limit: q.Limit}, nil
}

func (f *fakeReadableStore) Count(ctx context.Context, filters *output.Filters) (int64, error) {
	f.LastCountFilters = filters
	if f.CountFn != nil {
		return f.CountFn(ctx, filters)
	}
	return 0, nil
}

func (f *fakeReadableStore) CountBy(ctx context.Context, field string, filters *output.Filters) (map[string]int64, error) {
	f.LastCountByField = field
	if f.CountByFn != nil {
		return f.CountByFn(ctx, field, filters)
	}
	return nil, nil
}

func (f *fakeReadableStore) Histogram(ctx context.Context, req *output.HistogramRequest) (*output.HistogramResult, error) {
	f.LastHistogramReq = req
	if f.HistogramFn != nil {
		return f.HistogramFn(ctx, req)
	}
	if err := req.Normalize(); err != nil {
		return nil, err
	}
	return &output.HistogramResult{
		BucketMs: req.BucketMs,
		GroupBy:  req.GroupBy,
	}, nil
}

func (f *fakeReadableStore) GetEvent(ctx context.Context, uuid string) (*event.Event, error) {
	f.LastGetEventUUID = uuid
	if f.GetEventFn != nil {
		return f.GetEventFn(ctx, uuid)
	}
	return nil, nil
}

func buildTestServerWithStore(t *testing.T, store *fakeReadableStore) *Server {
	t.Helper()
	store.DriverName = testEventSourceName
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

	coreCfg := testConfig(t)
	coreCfg.UI.EventSource = testEventSourceName
	srv, err := NewServer(&ServerConfig{Pipeline: p, Catalog: newTestCatalog(t), Config: coreCfg})
	require.NoError(t, err)
	return srv
}

func buildUITestServer(t *testing.T, assets fs.FS, registry *prometheus.Registry) *Server {
	t.Helper()
	enricher, err := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	require.NoError(t, err)
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})

	srv, err := NewServer(&ServerConfig{
		Pipeline: p,
		Catalog:  newTestCatalog(t),
		UIAssets: assets,
		Registry: registry,
		Config:   testConfig(t),
	})
	require.NoError(t, err)
	return srv
}

type mutationTestRig struct {
	Server     *Server
	Reloader   *reload.Reloader
	Dispatcher *pipeline.Dispatcher
}

func newMutationTestCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.New([]output.Type{{
		Name: "slack",
		Schema: output.Schema{
			Fields: []output.SchemaField{
				{Name: "secret_endpoint", Type: "string", Required: true, Secret: true},
				{Name: "channel", Type: "string"},
			},
		},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "slack"}, nil
		},
	}})
	require.NoError(t, err)
	return cat
}

func buildMutationRig(t *testing.T, db core.Database, cat *catalog.Catalog, bindReloader bool) *mutationTestRig {
	t.Helper()
	dispatcher := pipeline.NewDispatcher(nil)
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	dispatcher.Start(workerRunCtx)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = dispatcher.Shutdown(ctx, stopWorkers)
	})

	r := reload.NewReloader(&reload.ReloaderConfig{
		OutputPaths:     nil,
		Catalog:         cat,
		Dispatcher:      dispatcher,
		Database:        db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})
	if bindReloader {
		r.BindWorkerContext(workerRunCtx, time.Second)
	}

	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})

	srv, err := NewServer(&ServerConfig{
		Pipeline: p,
		Database: db,
		Catalog:  cat,
		Reloader: r,
		Config:   writableConfig(),
	})
	require.NoError(t, err)
	return &mutationTestRig{Server: srv, Reloader: r, Dispatcher: dispatcher}
}

func buildMutationRigWithProvisioning(t *testing.T, db core.Database, cat *catalog.Catalog, prov core.ProvisioningConfig) *mutationTestRig {
	t.Helper()
	rig := buildMutationRig(t, db, cat, true)
	srv, err := NewServer(&ServerConfig{
		Pipeline: rig.Server.pipeline,
		Database: rig.Server.database,
		Catalog:  cat,
		Reloader: rig.Reloader,
		Config: &core.Config{
			Provisioning: prov,
			API:          core.APIConfig{AllowWrites: true},
		},
	})
	require.NoError(t, err)
	rig.Server = srv
	return rig
}

// seedOutput stores a new output entry, as a previous run would have left it.
func seedOutput(t *testing.T, db core.Database, name string, cfg map[string]any) {
	t.Helper()
	_, err := db.SaveOutputConfig(t.Context(), name, 0, cfg)
	require.NoError(t, err)
}

func buildMutationTestServer(t *testing.T, db core.Database) *Server {
	t.Helper()
	return buildMutationRig(t, db, newMutationTestCatalog(t), true).Server
}

func buildMutationTestServerNilReloader(t *testing.T, db core.Database) *Server {
	t.Helper()
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	p, err := pipeline.NewPipeline(enricher, pipeline.NewDispatcher(nil), nil)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})

	srv, err := NewServer(&ServerConfig{
		Pipeline: p,
		Database: db,
		Catalog:  newMutationTestCatalog(t),
		Reloader: nil,
		Config:   writableConfig(),
	})
	require.NoError(t, err)
	return srv
}

func writableConfig() *core.Config {
	return &core.Config{API: core.APIConfig{AllowWrites: true}}
}

func applyErr(_ int64, err error) error { return err }
