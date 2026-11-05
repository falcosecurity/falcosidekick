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

// ErrDBSyncFailed means the runtime change is live but was not persisted to the database.
var ErrDBSyncFailed = errors.New("reloader: database sync failed after runtime apply")

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
func (r *Reloader) ApplyOutput(ctx context.Context, name string, cfg map[string]any) error {
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

	cfgCopy := utils.DeepCopyMap(cfg)
	if err := config.ResolveSecrets(name, cfgCopy, outputType.Schema); err != nil {
		return r.fail(start, SourceUI, "apply secrets: %w", err)
	}

	out, err := pipeline.BuildOutput(ctx, r.catalog, name, cfgCopy, r.runtimeDefaults, r.deps)
	if err != nil {
		return r.fail(start, SourceUI, "apply %w", err)
	}

	retireCtx, retireCancel := context.WithTimeout(ctx, r.retireTimeout)
	defer retireCancel()

	_, fileOwned := r.fileState[name]
	existed := fileOwned
	if !existed {
		for _, n := range r.dispatcher.OutputNames() {
			if n == name {
				existed = true
				break
			}
		}
	}
	var retireWarning bool
	if existed {
		if err := r.dispatcher.ReplaceOutput(retireCtx, r.workerRunCtx, name, out); err != nil {
			if errors.Is(err, pipeline.ErrDispatcherStopped) {
				_ = out.Close()
				return r.fail(start, SourceUI, "%w", err)
			}
			retireWarning = true
			r.logger.Warn("apply: old output retire timeout, replacement active", "output", name, "error", err)
		}
	} else {
		if err := r.dispatcher.AddOutput(r.workerRunCtx, out); err != nil {
			if errors.Is(err, pipeline.ErrDispatcherStopped) {
				_ = out.Close()
				return r.fail(start, SourceUI, "%w", err)
			}
		}
	}

	var dbSyncFailed bool
	if r.database != nil {
		if err := r.database.SaveOutputConfig(ctx, name, cfgCopy); err != nil {
			dbSyncFailed = true
			r.logger.Error("apply: database save failed", "output", name, "error", err)
		}
	}

	// Updated even if the DB save failed, so the next file reload restores the file version.
	if fileOwned {
		r.fileState[name] = cfgCopy
	}

	duration := time.Since(start)
	if retireWarning || dbSyncFailed {
		r.metrics.recordPartialSuccess(duration, SourceUI)
	} else {
		r.metrics.recordSuccess(duration, SourceUI)
	}

	if dbSyncFailed {
		return ErrDBSyncFailed
	}
	return nil
}

// RemoveOutput retires an output and deletes it from the database, even if it is not running.
func (r *Reloader) RemoveOutput(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.bound {
		return ErrReloaderNotBound
	}

	start := time.Now()

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

	var dbSyncFailed bool
	if r.database != nil {
		if err := r.database.DeleteOutputConfig(ctx, name); err != nil {
			dbSyncFailed = true
			r.logger.Error("remove: database delete failed", "output", name, "error", err)
		}
	}

	// The next file reload then sees the name as added and restores a file-provisioned output.
	delete(r.fileState, name)

	duration := time.Since(start)
	if retireWarning || dbSyncFailed {
		r.metrics.recordPartialSuccess(duration, SourceUI)
	} else {
		r.metrics.recordSuccess(duration, SourceUI)
	}

	if dbSyncFailed {
		return ErrDBSyncFailed
	}
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

	for name := range outsCfg.Outputs {
		if _, ok := r.catalog.Get(name); !ok {
			return r.fail(start, SourceFile, "reload validate: unknown output type %q", name)
		}
	}

	for name, outputCfg := range outsCfg.Outputs {
		outputType, _ := r.catalog.Get(name) // validated above
		if err := config.ResolveSecrets(name, outputCfg, outputType.Schema); err != nil {
			return r.fail(start, SourceFile, "reload secrets: %w", err)
		}
	}

	diff := DiffOutputConfigs(r.fileState, outsCfg.Outputs)

	// A live name goes through ReplaceOutput so AddOutput never leaks a running worker.
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

	addedOutputs, err := r.createOutputs(ctx, diff.Added)
	if err != nil {
		return r.fail(start, SourceFile, "reload create added: %w", err)
	}

	changedOutputs, err := r.createOutputs(ctx, diff.Changed)
	if err != nil {
		closeOutputs(addedOutputs)
		return r.fail(start, SourceFile, "reload create changed: %w", err)
	}

	retireCtx, retireCancel := context.WithTimeout(ctx, retireTimeout)
	defer retireCancel()

	// retireWarning means a drain timed out but the replacement is live.
	var stopped bool
	var retireWarning bool

	for _, out := range addedOutputs {
		if err := r.dispatcher.AddOutput(workerRunCtx, out); err != nil {
			if errors.Is(err, pipeline.ErrDispatcherStopped) {
				_ = out.Close()
				stopped = true
				r.logger.Warn("reload: add rejected, dispatcher stopped", "output", out.Name())
			}
		}
	}
	for name, out := range changedOutputs {
		if err := r.dispatcher.ReplaceOutput(retireCtx, workerRunCtx, name, out); err != nil {
			if errors.Is(err, pipeline.ErrDispatcherStopped) {
				_ = out.Close()
				stopped = true
				r.logger.Warn("reload: replace rejected, dispatcher stopped", "output", name)
			} else {
				retireWarning = true
				r.logger.Warn("reload: old output retire timeout, replacement active", "output", name, "error", err)
			}
		}
	}
	if !r.provisioning.DisableDeletion {
		for _, name := range diff.Removed {
			if err := r.dispatcher.RemoveOutput(retireCtx, name); err != nil {
				if errors.Is(err, pipeline.ErrDispatcherStopped) {
					stopped = true
					r.logger.Warn("reload: remove rejected, dispatcher stopped", "output", name)
				} else {
					retireWarning = true
					r.logger.Warn("reload: removed output retire timeout", "output", name, "error", err)
				}
			}
		}
	}

	if stopped {
		return r.fail(start, SourceFile, "reload abandoned: dispatcher stopped during apply")
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
	r.fileState = outsCfg.Outputs
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

func (r *Reloader) fail(start time.Time, source, format string, args ...any) error {
	r.metrics.recordFailure(time.Since(start), source)
	return fmt.Errorf(format, args...)
}
