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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/api"
	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/reload"
	"github.com/falcosecurity/falcosidekick/internal/utils"
	"github.com/falcosecurity/falcosidekick/ui"
)

type app struct {
	db       core.Database
	pipe     *pipeline.Pipeline
	srv      *api.Server
	reloader *reload.Reloader
	// background holds the reload trigger and replica sync goroutines, which stop with the app context.
	background sync.WaitGroup
}

// NewApp builds all application resources and closes them on failure.
func NewApp(
	ctx context.Context,
	cfg *config.Config,
	outsCfg *config.OutputsConfig,
	collector *metrics.Collector,
	cat *catalog.Catalog,
	logger *slog.Logger,
) (_ *app, retErr error) {
	if err := config.CheckEventSource(&cfg.UI, cat); err != nil {
		return nil, err
	}
	persistent := cfg.Database.Backend.Persistent()
	if persistent {
		if err := config.CheckNoInlineSecrets(outsCfg.Outputs, cat); err != nil {
			return nil, fmt.Errorf("output files: %w", err)
		}
		if cfg.API.AllowWrites && len(cfg.API.SecretDirs) == 0 {
			logger.Warn("api.secret_dirs is empty: outputs with secrets cannot be created through the API",
				"backend", cfg.Database.Backend)
		}
	}

	// Outputs are built from resolved secret files; the database keeps the configs as written.
	resolved, err := config.ResolvedOutputs(outsCfg.Outputs, cat)
	if err != nil {
		return nil, fmt.Errorf("secret resolution: %w", err)
	}

	db, err := createDatabase(ctx, &cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = db.Close()
		}
	}()

	enricher, err := pipeline.NewEnricher(cfg.Enricher)
	if err != nil {
		return nil, fmt.Errorf("enricher: %w", err)
	}

	outputs, err := createOutputs(ctx, cfg, resolved, cat, collector)
	if err != nil {
		return nil, fmt.Errorf("outputs: %w", err)
	}
	defer func() {
		if retErr != nil {
			closeOutputs(outputs)
		}
	}()

	// File outputs are provisioned only once they built, so a broken file never reaches the store.
	if err := db.Provision(ctx, &core.ProvisionRequest{Outputs: outsCfg.Outputs}); err != nil {
		return nil, fmt.Errorf("database provision: %w", err)
	}
	slog.Info("database provisioned", "backend", cfg.Database.Backend, "outputs", len(outsCfg.Outputs))

	restored, err := restoreFromDB(ctx, cfg, db, cat, collector, outsCfg.Outputs)
	if err != nil {
		return nil, fmt.Errorf("restore outputs: %w", err)
	}
	defer func() {
		if retErr != nil {
			closeOutputs(restored.outputs)
		}
	}()
	outputs = append(outputs, restored.outputs...)

	dispatcher := pipeline.NewDispatcher(outputs)
	for name, failure := range restored.failures {
		dispatcher.MarkFailed(name, "not started: "+failure.Error())
	}

	if cfg.UI.Enabled {
		if _, ok := dispatcher.GetReadableStore(cfg.UI.EventSource); !ok {
			// A stored output that did not build is reported failed; until it runs the events API answers 503.
			if _, failed := restored.failures[cfg.UI.EventSource]; !failed {
				return nil, errors.New("ui.event_source: output not found or does not implement ReadableStore")
			}
			logger.Warn("ui.event_source did not start; the events API answers 503 until it runs", "output", cfg.UI.EventSource)
		}
	}

	pipe, err := pipeline.NewPipeline(enricher, dispatcher, collector)
	if err != nil {
		return nil, fmt.Errorf("pipeline: %w", err)
	}

	uiAssets := resolveUIAssets(cfg.UI.Enabled, ui.Dist)

	reloader := reload.NewReloader(&reload.ReloaderConfig{
		OutputPaths:         outsCfg.Paths,
		Catalog:             cat,
		Dispatcher:          dispatcher,
		Database:            db,
		RuntimeDefaults:     cfg.RuntimeDefaults,
		Provisioning:        cfg.Provisioning,
		Deps:                output.Deps{Logger: logger, Metrics: collector},
		Registry:            collector.Registry(),
		Logger:              logger,
		InitialOutputs:      resolved,
		FileOutputs:         outsCfg.Outputs,
		APIOutputs:          restored.resolved,
		APIVersions:         restored.builtVersions(),
		FailedAPIVersions:   restored.failedVersions(),
		RejectInlineSecrets: persistent,
	})

	srv, err := api.NewServer(&api.ServerConfig{
		Pipeline: pipe,
		Database: db,
		Catalog:  cat,
		Metrics:  collector,
		Registry: collector.Registry(),
		Config:   &cfg.Config,
		Reloader: reloader,
		UIAssets: uiAssets,
		Logger:   logger,
	})
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	return &app{
		db:       db,
		pipe:     pipe,
		srv:      srv,
		reloader: reloader,
	}, nil
}

// startReloadWatchers binds the worker context so UI-driven applies share the file reload lifetime.
// Output files, secret directories and SIGHUP trigger a reload, which rebuilds only what changed.
func (a *app) startReloadWatchers(
	appCtx, workerRunCtx context.Context,
	outputPaths, secretDirs []string,
	reloadCfg core.ReloadConfig,
) {
	a.reloader.BindWorkerContext(workerRunCtx, reloadCfg.RetireTimeout)

	secrets := reload.NewSecretPaths(secretDirs, a.reloader.FilePaths)
	// Only output files add file outputs, so without them the secret directories are the roots alone.
	watch := len(outputPaths) > 0 || len(secretDirs) > 0

	// A reload can change the files the file outputs read, so the watcher syncs its directories after it.
	var watcher *reload.Watcher
	reloadFn := func() error {
		err := a.reloader.Reload(appCtx, workerRunCtx, reloadCfg.RetireTimeout)
		if watcher != nil {
			watcher.Refresh()
		}
		return err
	}

	if watch {
		watcher = reload.NewWatcher(outputPaths, secrets.Dirs, 100*time.Millisecond, reloadFn, slog.Default())
		a.background.Go(func() {
			if err := watcher.Run(appCtx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("watcher stopped", "error", err)
			}
		})
	}

	if watch && reloadCfg.PollInterval > 0 {
		poller := reload.NewPoller(outputPaths, secrets.Files, reloadCfg.PollInterval, reloadFn, slog.Default())
		a.background.Go(func() {
			if err := poller.Run(appCtx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("poller stopped", "error", err)
			}
		})
	}

	// SIGHUP also rereads the secret files of API outputs, so it runs without output files too.
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	a.background.Go(func() {
		for {
			select {
			case <-appCtx.Done():
				signal.Stop(sigHUP)
				return
			case <-sigHUP:
				slog.Info("received SIGHUP, reloading output config")
				if err := reloadFn(); err != nil {
					slog.Error("reload failed (SIGHUP)", "error", err)
				}
			}
		}
	})
}

func (a *app) serve(errCh chan<- error) {
	go func() {
		if err := a.srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
}

// startReplicaSync keeps the API outputs of this instance in step with the shared postgres database:
// a reconcile runs on each change notification, after each (re)connection of the listener, and every
// poll_interval, since notifications can be lost. Other backends have a single instance.
func (a *app) startReplicaSync(appCtx context.Context, cfg *core.DatabaseConfig) error {
	if cfg.Backend != core.DatabasePostgres {
		return nil
	}
	settings, err := database.PostgresSettings(&cfg.Postgres)
	if err != nil {
		return err
	}
	settings.ConnectTimeout = cfg.ConnectTimeout
	pending := make(chan struct{}, 1)
	request := func() {
		select {
		case pending <- struct{}{}:
		default:
		}
	}
	a.background.Go(func() { database.ListenOutputChanges(appCtx, settings, request, slog.Default()) })
	a.background.Go(func() {
		ticker := time.NewTicker(cfg.Postgres.PollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-appCtx.Done():
				return
			case <-ticker.C:
				request()
			}
		}
	})
	a.background.Go(func() {
		for {
			select {
			case <-appCtx.Done():
				return
			case <-pending:
				if appCtx.Err() != nil {
					return
				}
				if err := a.reloader.Reconcile(appCtx); err != nil && !errors.Is(err, reload.ErrReloaderClosed) {
					slog.Warn("reconcile with the database failed; retrying at the next change or poll", "error", err)
				}
			}
		}
	})
	return nil
}

func (a *app) shutdown() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown", "error", err)
	}

	// A write still in flight past the server deadline finishes here; later ones are refused,
	// so no stored change is left unapplied when the pipeline stops.
	a.reloader.Close()

	if err := a.pipe.Shutdown(shutdownCtx); err != nil {
		slog.Warn("pipeline shutdown: deadline exceeded, deferred cleanup may continue asynchronously", "error", err)
	}

	a.background.Wait()
	if err := a.db.Close(); err != nil {
		slog.Error("database close", "error", err)
	}

	slog.Info("stopped")
}

// resolveUIAssets returns nil without -tags=builtinui so event ingestion still starts.
func resolveUIAssets(enabled bool, dist fs.FS) fs.FS {
	if !enabled {
		return nil
	}
	if dist == nil {
		slog.Warn("ui enabled in config but binary built without -tags=builtinui; API will serve, UI will not")
		return nil
	}
	return dist
}

// createDatabase opens the configured backend; opening and migrating are bounded by connect_timeout.
func createDatabase(ctx context.Context, cfg *core.DatabaseConfig) (core.Database, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	switch cfg.Backend {
	case core.DatabaseInMemory:
		return database.NewMemory(), nil
	case core.DatabaseSQLite:
		return database.OpenSQLite(ctx, cfg.SQLite.Path)
	case core.DatabasePostgres:
		settings, err := database.PostgresSettings(&cfg.Postgres)
		if err != nil {
			return nil, err
		}
		return database.OpenPostgres(ctx, settings, cfg.Postgres.MaxConnections)
	default:
		return nil, fmt.Errorf("database backend %q not supported", cfg.Backend)
	}
}

func createOutputs(
	ctx context.Context,
	cfg *config.Config,
	rawOutputs map[string]map[string]any,
	cat *catalog.Catalog,
	mc core.MetricsCollector,
) ([]*pipeline.Output, error) {
	deps := output.Deps{Logger: slog.Default(), Metrics: mc}
	built, err := pipeline.BuildOutputs(ctx, cat, rawOutputs, cfg.RuntimeDefaults, deps)
	if err != nil {
		return nil, err
	}
	outputs := make([]*pipeline.Output, 0, len(built))
	for _, name := range slices.Sorted(maps.Keys(built)) {
		outputs = append(outputs, built[name])
		slog.Info("output enabled", "output", name)
	}
	return outputs, nil
}

// restoredOutputs are the stored API outputs rebuilt at startup.
type restoredOutputs struct {
	// resolved holds the configs of the outputs that built, with secret files read.
	resolved map[string]map[string]any
	failures map[string]error
	// versions holds the stored version of every restored output, built or failed.
	versions map[string]int64
	outputs  []*pipeline.Output
}

func (r *restoredOutputs) builtVersions() map[string]int64 {
	result := make(map[string]int64, len(r.resolved))
	for name := range r.resolved {
		result[name] = r.versions[name]
	}
	return result
}

func (r *restoredOutputs) failedVersions() map[string]int64 {
	result := make(map[string]int64, len(r.failures))
	for name := range r.failures {
		result[name] = r.versions[name]
	}
	return result
}

// restoreFromDB rebuilds outputs stored in the database but absent from the output files.
// A stored output that does not build is left out and returned with its failure; its row is kept.
func restoreFromDB(
	ctx context.Context,
	cfg *config.Config,
	db core.Database,
	cat *catalog.Catalog,
	mc core.MetricsCollector,
	fileOutputs map[string]map[string]any,
) (*restoredOutputs, error) {
	entries, err := db.GetOutputConfigs(ctx)
	if err != nil {
		return nil, fmt.Errorf("read persisted outputs: %w", err)
	}
	resolved := make(map[string]map[string]any)
	failures := make(map[string]error)
	versions := make(map[string]int64)
	for name, entry := range entries {
		if _, inFiles := fileOutputs[name]; inFiles {
			continue
		}
		versions[name] = entry.Version
		outputType, ok := cat.Get(name)
		if !ok {
			failures[name] = fmt.Errorf("unknown output type %q", name)
			continue
		}
		cfgCopy := utils.DeepCopyMap(entry.Config)
		if err := config.ResolveSecrets(name, cfgCopy, outputType.Schema); err != nil {
			failures[name] = err
			continue
		}
		resolved[name] = cfgCopy
	}

	built, buildFailures := pipeline.BuildEach(ctx, cat, resolved, cfg.RuntimeDefaults, output.Deps{Logger: slog.Default(), Metrics: mc})
	maps.Copy(failures, buildFailures)
	restored := &restoredOutputs{resolved: make(map[string]map[string]any, len(built)), failures: failures, versions: versions}
	for _, name := range slices.Sorted(maps.Keys(built)) {
		restored.outputs = append(restored.outputs, built[name])
		restored.resolved[name] = resolved[name]
		slog.Info("output enabled", "output", name)
	}
	for _, name := range slices.Sorted(maps.Keys(failures)) {
		slog.Error("stored output not started", "output", name, "error", failures[name])
	}
	return restored, nil
}

func closeOutputs(outputs []*pipeline.Output) {
	for _, out := range outputs {
		if err := out.Close(); err != nil {
			slog.Warn("output close during cleanup", "output", out.Name(), "error", err)
		}
	}
}
