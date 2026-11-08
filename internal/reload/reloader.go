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

// ReloaderConfig holds the dependencies the Reloader needs. Long-lived
// contexts are not stored here; they are passed explicitly to Reload.
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

// ErrReloaderNotBound is returned by ApplyOutput and RemoveOutput when
// BindWorkerContext has not been called yet.
var ErrReloaderNotBound = errors.New("reloader: worker context not bound")

// ErrUnknownOutputType is returned by ApplyOutput when the requested name
// is not registered in the catalog.
var ErrUnknownOutputType = errors.New("reloader: unknown output type")

// ErrDBSyncFailed is returned by ApplyOutput and RemoveOutput when the
// runtime change was applied to the dispatcher but the subsequent
// database persistence step failed. Runtime state is live but not
// durable; the caller must surface this to the operator.
var ErrDBSyncFailed = errors.New("reloader: database sync failed after runtime apply")

// Reloader applies output config changes to a running dispatcher from two
// sources: file reloads (Reload) and UI writes (ApplyOutput, RemoveOutput).
// All apply paths serialize on an internal mutex so runtime state changes
// are strictly sequential across sources.
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

// NewReloader returns a Reloader. InitialOutputs is deep-copied so the
// reloader's diff state is isolated from the caller.
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

// BindWorkerContext attaches the long-lived worker context and retire
// timeout that ApplyOutput and RemoveOutput use when building or retiring
// outputs. Must be called exactly once before the first UI-driven apply.
// Panics if called a second time.
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

// ApplyOutput applies one UI-driven output config to the dispatcher
// and persists it through Database.SaveOutputConfig. r.fileState records
// names whose last-applied source was a file; ApplyOutput updates it
// only when the name is already present so UI-only names stay out of
// the file view.
//
// Returns nil on full success, ErrDBSyncFailed when runtime applied
// but Database.SaveOutputConfig failed, ErrUnknownOutputType when the
// name has no catalog entry, ErrReloaderNotBound before the worker
// context binding, or pipeline.ErrDispatcherStopped during shutdown.
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

	// r.fileState tracks runtime state for file-owned names so the next
	// file reload can detect divergence and restore the file version.
	// The update happens regardless of dbSyncFailed: the dispatcher
	// was mutated either way, and the next reload must see that to
	// restore the file on partial failure.
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

// RemoveOutput retires a single output from the dispatcher and deletes
// it from the database. A name that is not currently running is still
// valid: the dispatcher returns nil and the DB delete is attempted.
//
// Outcomes mirror ApplyOutput:
//   - nil: runtime retired AND database deleted. Metric success (or
//     partial_success if retire timed out while replacement/retire was
//     in-flight).
//   - ErrDBSyncFailed: runtime retired but database delete failed.
//     Metric partial_success.
//   - pipeline.ErrDispatcherStopped: shutdown in progress; neither
//     runtime nor DB mutated. Metric failure.
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

	// Drop the name from the file view so the next file reload
	// detects the delete as an addition and restores file-provisioned
	// outputs without requiring a file edit.
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

// Reload diffs the current output config files against the running state
// and applies the delta. On any pre-apply failure the running state is
// left unchanged.
//
// ctx bounds parse, Init, and DB Provision; typically derived from the
// process context. workerRunCtx is attached to new output workers so
// they outlive ctx cancellation during a clean shutdown. retireTimeout
// bounds retirement of old outputs only.
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

	// Route names already live in the dispatcher through ReplaceOutput
	// so AddOutput never overwrites a running slot and leaks its worker.
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

	// stopped means the dispatcher rejected a mutation (shutdown in progress);
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
	// With DisableDeletion=true, names that dropped out of the file
	// set are preserved as orphaned provisioned outputs: keep them
	// running in the dispatcher and keep their DB entries.
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

	// Runtime apply succeeded past this point, so r.fileState always advances
	// regardless of DB sync or retire-timeout outcome. When DisableDeletion
	// is on, orphaned names still drop out of r.fileState so subsequent
	// reloads do not keep retrying to retire them.
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

// createOutputs builds the given set of outputs. On failure, outputs built
// so far in the batch are closed before returning.
func (r *Reloader) createOutputs(ctx context.Context, configs map[string]map[string]any) (map[string]*pipeline.Output, error) {
	outputs := make(map[string]*pipeline.Output, len(configs))

	for name, cfg := range configs {
		out, err := pipeline.BuildOutput(ctx, r.catalog, name, cfg, r.runtimeDefaults, r.deps)
		if err != nil {
			closeOutputs(outputs)
			return nil, fmt.Errorf("output %q %w", name, err)
		}
		outputs[name] = out
	}

	return outputs, nil
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
