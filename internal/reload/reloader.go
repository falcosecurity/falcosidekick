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

package reload

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// ReloaderConfig holds the Reloader dependencies; contexts are passed to Reload and BindWorkerContext.
type ReloaderConfig struct {
	Deps            output.Deps
	Database        core.Database
	Registry        prometheus.Registerer
	Catalog         *catalog.Catalog
	Dispatcher      *pipeline.Dispatcher
	Logger          *slog.Logger
	InitialOutputs  map[string]map[string]any
	OutputPaths     []string
	RuntimeDefaults output.RuntimeConfig
	Provisioning    core.ProvisioningConfig
}

// ErrReloaderNotBound is returned by UI writes before BindWorkerContext is called.
var ErrReloaderNotBound = errors.New("reloader: worker context not bound")

// ErrUnknownOutputType is returned by ApplyOutput for a name not in the catalog.
var ErrUnknownOutputType = errors.New("reloader: unknown output type")

// ErrDatabaseUnavailable means a write did not reach the database; nothing was applied.
var ErrDatabaseUnavailable = errors.New("reloader: database write failed, nothing was applied")

// Reloader applies output config changes from file reloads and UI writes, serialized by one mutex.
type Reloader struct {
	deps       output.Deps
	database   core.Database
	catalog    *catalog.Catalog
	dispatcher *pipeline.Dispatcher
	metrics    *reloadMetrics

	fileState       map[string]map[string]any
	logger          *slog.Logger
	workerRunCtx    context.Context
	outputPaths     []string
	runtimeDefaults output.RuntimeConfig
	retireTimeout   time.Duration
	provisioning    core.ProvisioningConfig
	mu              sync.Mutex
	bound           bool
}

// NewReloader returns a Reloader with its own deep copy of InitialOutputs.
func NewReloader(cfg *ReloaderConfig) *Reloader {
	var initial map[string]map[string]any
	if cfg.InitialOutputs != nil {
		initial = make(map[string]map[string]any, len(cfg.InitialOutputs))
		for name, m := range cfg.InitialOutputs {
			initial[name] = utils.DeepCopyMap(m)
		}
	}
	return &Reloader{
		outputPaths:     cfg.OutputPaths,
		catalog:         cfg.Catalog,
		dispatcher:      cfg.Dispatcher,
		database:        cfg.Database,
		runtimeDefaults: cfg.RuntimeDefaults,
		provisioning:    cfg.Provisioning,
		deps:            cfg.Deps,
		metrics:         newReloadMetrics(cfg.Registry),
		fileState:       initial,
		logger:          cfg.Logger,
	}
}

// BindWorkerContext sets the worker context and retire timeout for UI writes; it panics if called twice.
func (r *Reloader) BindWorkerContext(workerRunCtx context.Context, retireTimeout time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bound {
		panic("reload: BindWorkerContext called twice")
	}
	r.workerRunCtx = workerRunCtx
	r.retireTimeout = retireTimeout
	r.bound = true
}

// ApplyOutput applies one UI-driven output config to the dispatcher and persists it.
// version is the stored version cfg was built from, 0 for an output not stored yet;
// with a database, any other stored version returns ErrVersionConflict.
func (r *Reloader) ApplyOutput(ctx context.Context, name string, version int64, cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.bound {
		return ErrReloaderNotBound
	}

	start := time.Now()

	outputType, ok := r.catalog.Get(name)
	if !ok {
		return r.fail(start, SourceUI, "%w: %q", ErrUnknownOutputType, name)
	}

	if err := r.checkVersion(ctx, name, version); err != nil {
		return r.fail(start, SourceUI, "%w", err)
	}

	// The output is built from resolved secret files; the database keeps the config as written.
	stored := utils.DeepCopyMap(cfg)
	resolved := utils.DeepCopyMap(cfg)
	if err := config.ResolveSecrets(name, resolved, outputType.Schema); err != nil {
		return r.fail(start, SourceUI, "apply secrets: %w: %w", pipeline.ErrInvalidOutputConfig, err)
	}

	out, err := pipeline.BuildOutput(ctx, r.catalog, name, resolved, r.runtimeDefaults, r.deps)
	if err != nil {
		return r.fail(start, SourceUI, "apply %w", err)
	}

	// The database decides first: a refused write leaves the running output untouched.
	if err := r.writeOutput(ctx, name, version, stored); err != nil {
		_ = out.Close()
		return r.fail(start, SourceUI, "%w", err)
	}

	retireCtx, retireCancel := context.WithTimeout(ctx, r.retireTimeout)
	defer retireCancel()

	var retireWarning bool
	if err := r.dispatcher.ReplaceOutput(retireCtx, r.workerRunCtx, name, out); err != nil {
		if errors.Is(err, pipeline.ErrDispatcherStopped) {
			_ = out.Close()
			return r.fail(start, SourceUI, "%w", err)
		}
		retireWarning = true
		r.logger.Warn("apply: old output retire timeout, replacement active", "output", name, "error", err)
	}

	if _, fileOwned := r.fileState[name]; fileOwned {
		r.fileState[name] = resolved
	}

	r.recordUI(start, retireWarning)
	return nil
}

// RemoveOutput retires an output and deletes it from the database, even if it is not running.
// version is the stored version the caller read; with a database, any other returns ErrVersionConflict.
func (r *Reloader) RemoveOutput(ctx context.Context, name string, version int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.bound {
		return ErrReloaderNotBound
	}

	start := time.Now()

	// The database decides first: a refused delete leaves the running output untouched.
	if r.database != nil {
		if err := r.database.DeleteOutputConfig(ctx, name, version); err != nil {
			return r.fail(start, SourceUI, "%w", databaseError(err))
		}
	}

	retireCtx, retireCancel := context.WithTimeout(ctx, r.retireTimeout)
	defer retireCancel()

	var retireWarning bool
	if err := r.dispatcher.RemoveOutput(retireCtx, name); err != nil {
		if errors.Is(err, pipeline.ErrDispatcherStopped) {
			return r.fail(start, SourceUI, "%w", err)
		}
		retireWarning = true
		r.logger.Warn("remove: output retire timeout", "output", name, "error", err)
	}

	// The next file reload then sees the name as added and restores a file-provisioned output.
	delete(r.fileState, name)

	r.recordUI(start, retireWarning)
	return nil
}

// Reload applies the delta between the output config files and the running state.
// ctx bounds parse, Init and Provision; new workers run on workerRunCtx so they outlive ctx.
func (r *Reloader) Reload(ctx, workerRunCtx context.Context, retireTimeout time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	start := time.Now()

	outsCfg, err := config.LoadOutputs(r.outputPaths)
	if err != nil {
		return r.fail(start, SourceFile, "reload parse: %w", err)
	}

	// fileState and the builds use resolved copies, so a rotated secret file is a change;
	// the database gets the configs as written.
	resolved, err := config.ResolvedOutputs(outsCfg.Outputs, r.catalog)
	if err != nil {
		return r.fail(start, SourceFile, "reload secrets: %w", err)
	}

	diff := DiffOutputConfigs(r.fileState, resolved)

	// A name added to the files but already running, from the API, is a change: Apply replaces it.
	for _, name := range r.dispatcher.OutputNames() {
		if cfg, added := diff.Added[name]; added {
			diff.Changed[name] = cfg
			delete(diff.Added, name)
		}
	}

	if diff.IsEmpty() {
		r.logger.Debug("reload: no output config changes detected")
		r.metrics.recordNoop(SourceFile)
		return nil
	}

	// One concurrent build of every added and changed output; a failure leaves the running set untouched.
	toBuild := make(map[string]map[string]any, len(diff.Added)+len(diff.Changed))
	maps.Copy(toBuild, diff.Added)
	maps.Copy(toBuild, diff.Changed)
	built, err := r.createOutputs(ctx, toBuild)
	if err != nil {
		return r.fail(start, SourceFile, "reload create: %w", err)
	}

	var removed []string
	if !r.provisioning.DisableDeletion {
		removed = diff.Removed
	}

	retireCtx, retireCancel := context.WithTimeout(ctx, retireTimeout)
	defer retireCancel()

	// retireWarning means a drain timed out but the replacement is live.
	var retireWarning bool
	if err := r.dispatcher.Apply(retireCtx, workerRunCtx, built, removed); err != nil {
		if errors.Is(err, pipeline.ErrDispatcherStopped) {
			closeOutputs(built)
			return r.fail(start, SourceFile, "reload abandoned: dispatcher stopped during apply")
		}
		retireWarning = true
		r.logger.Warn("reload: retire timeout, replacements active", "error", err)
	}

	var dbSyncFailed bool
	if r.database != nil {
		if err := r.database.Provision(ctx, &core.ProvisionRequest{
			Outputs:         outsCfg.Outputs,
			DisableDeletion: r.provisioning.DisableDeletion,
		}); err != nil {
			dbSyncFailed = true
			r.logger.Error("reload: database re-provision failed", "error", err)
		}
	}

	// The runtime is applied, so fileState advances even on DB or retire failure;
	// orphans kept by DisableDeletion leave it so later reloads do not retire them.
	r.fileState = resolved
	duration := time.Since(start)

	if retireWarning || dbSyncFailed {
		r.metrics.recordPartialSuccess(duration, SourceFile)
		r.logger.Warn("reload partial",
			"added", len(diff.Added),
			"changed", len(diff.Changed),
			"removed", len(diff.Removed),
			"retire_warning", retireWarning,
			"db_sync_failed", dbSyncFailed,
			"duration", duration,
		)
	} else {
		r.metrics.recordSuccess(duration, SourceFile)
		r.logger.Info("reload complete",
			"added", len(diff.Added),
			"changed", len(diff.Changed),
			"removed", len(diff.Removed),
			"duration", duration,
		)
	}
	return nil
}

func (r *Reloader) createOutputs(ctx context.Context, configs map[string]map[string]any) (map[string]*pipeline.Output, error) {
	return pipeline.BuildOutputs(ctx, r.catalog, configs, r.runtimeDefaults, r.deps)
}

func closeOutputs(outputs map[string]*pipeline.Output) {
	for _, out := range outputs {
		_ = out.Close()
	}
}

// checkVersion refuses a stale write before an output is built for it; the write itself is conditional too.
func (r *Reloader) checkVersion(ctx context.Context, name string, version int64) error {
	if r.database == nil {
		return nil
	}
	stored, err := r.database.GetOutputConfig(ctx, name)
	if err != nil {
		return databaseError(err)
	}
	var current int64
	if stored != nil {
		current = stored.Version
	}
	if current != version {
		return core.ErrVersionConflict
	}
	return nil
}

func (r *Reloader) writeOutput(ctx context.Context, name string, version int64, cfg map[string]any) error {
	if r.database == nil {
		return nil
	}
	_, err := r.database.SaveOutputConfig(ctx, name, version, cfg)
	return databaseError(err)
}

// databaseError keeps a version conflict and turns any other database failure into ErrDatabaseUnavailable.
func databaseError(err error) error {
	switch {
	case err == nil, errors.Is(err, core.ErrVersionConflict):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrDatabaseUnavailable, err)
	}
}

func (r *Reloader) recordUI(start time.Time, retireWarning bool) {
	if retireWarning {
		r.metrics.recordPartialSuccess(time.Since(start), SourceUI)
		return
	}
	r.metrics.recordSuccess(time.Since(start), SourceUI)
}

func (r *Reloader) fail(start time.Time, source, format string, args ...any) error {
	r.metrics.recordFailure(time.Since(start), source)
	return fmt.Errorf(format, args...)
}
