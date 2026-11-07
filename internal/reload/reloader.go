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
	"reflect"
	"slices"
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
	Deps       output.Deps
	Database   core.Database
	Registry   prometheus.Registerer
	Catalog    *catalog.Catalog
	Dispatcher *pipeline.Dispatcher
	Logger     *slog.Logger
	// InitialOutputs are the file outputs running at startup, built from resolved secret files.
	InitialOutputs map[string]map[string]any
	// FileOutputs are the same outputs as written in the files, as they were provisioned.
	FileOutputs map[string]map[string]any
	// APIOutputs are the stored API outputs running at startup, built from resolved secret files.
	APIOutputs map[string]map[string]any
	// APIVersions are the stored versions of APIOutputs; FailedAPIVersions those that did not build at startup.
	APIVersions       map[string]int64
	FailedAPIVersions map[string]int64
	OutputPaths       []string
	RuntimeDefaults   output.RuntimeConfig
	Provisioning      core.ProvisioningConfig
	// RejectInlineSecrets fails a reload whose files write a secret inline, for a persistent database.
	RejectInlineSecrets bool
}

// ErrReloaderNotBound is returned by UI writes before BindWorkerContext is called.
var ErrReloaderNotBound = errors.New("reloader: worker context not bound")

// ErrReloaderClosed is returned by every change after Close; nothing was applied or stored.
var ErrReloaderClosed = errors.New("reloader: shutting down")

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

	// fileState holds the file outputs with resolved secrets, fileRaw the same outputs as written.
	fileState map[string]map[string]any
	fileRaw   map[string]map[string]any
	// apiState holds the running API outputs with resolved secrets, to see a rotated secret file.
	apiState map[string]map[string]any
	// apiVersions holds the stored version each running API output was built from, apiFailed the
	// version of each API output change that did not build here.
	apiVersions     map[string]int64
	apiFailed       map[string]int64
	logger          *slog.Logger
	workerRunCtx    context.Context
	outputPaths     []string
	runtimeDefaults output.RuntimeConfig
	retireTimeout   time.Duration
	rejectInline    bool
	provisioning    core.ProvisioningConfig
	mu              sync.Mutex
	bound           bool
	closed          bool
}

// NewReloader returns a Reloader with its own deep copies of InitialOutputs and FileOutputs.
func NewReloader(cfg *ReloaderConfig) *Reloader {
	return &Reloader{
		outputPaths:     cfg.OutputPaths,
		catalog:         cfg.Catalog,
		dispatcher:      cfg.Dispatcher,
		database:        cfg.Database,
		runtimeDefaults: cfg.RuntimeDefaults,
		provisioning:    cfg.Provisioning,
		deps:            cfg.Deps,
		metrics:         newReloadMetrics(cfg.Registry),
		fileState:       copyConfigs(cfg.InitialOutputs),
		fileRaw:         copyConfigs(cfg.FileOutputs),
		apiState:        copyConfigs(cfg.APIOutputs),
		apiVersions:     copyVersions(cfg.APIVersions),
		apiFailed:       copyVersions(cfg.FailedAPIVersions),
		rejectInline:    cfg.RejectInlineSecrets,
		logger:          cfg.Logger,
	}
}

func copyVersions(versions map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(versions))
	maps.Copy(result, versions)
	return result
}

func copyConfigs(configs map[string]map[string]any) map[string]map[string]any {
	result := make(map[string]map[string]any, len(configs))
	for name, cfg := range configs {
		result[name] = utils.DeepCopyMap(cfg)
	}
	return result
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

// Close waits for the change in progress and refuses every later one, so the pipeline can stop
// without a stored change left unapplied.
func (r *Reloader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
}

// ApplyOutput applies one UI-driven output config to the dispatcher and persists it, returning the
// stored version. version is the stored version cfg was built from, 0 for an output not stored yet;
// with a database, any other stored version returns core.ErrVersionConflict.
func (r *Reloader) ApplyOutput(ctx context.Context, name string, version int64, cfg map[string]any) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return 0, ErrReloaderClosed
	}
	if !r.bound {
		return 0, ErrReloaderNotBound
	}

	start := time.Now()

	outputType, ok := r.catalog.Get(name)
	if !ok {
		return 0, r.fail(start, SourceUI, "%w: %q", ErrUnknownOutputType, name)
	}

	if err := r.checkVersion(ctx, name, version); err != nil {
		return 0, r.fail(start, SourceUI, "%w", err)
	}

	// The output is built from resolved secret files; the database keeps the config as written.
	stored := utils.DeepCopyMap(cfg)
	resolved := utils.DeepCopyMap(cfg)
	if err := config.ResolveSecrets(name, resolved, outputType.Schema); err != nil {
		return 0, r.fail(start, SourceUI, "apply secrets: %w: %w", pipeline.ErrInvalidOutputConfig, err)
	}

	out, err := pipeline.BuildOutput(ctx, r.catalog, name, resolved, r.runtimeDefaults, r.deps)
	if err != nil {
		return 0, r.fail(start, SourceUI, "apply %w", err)
	}

	// The database decides first: a refused write leaves the running output untouched.
	newVersion, err := r.writeOutput(ctx, name, version, stored)
	if err != nil {
		_ = out.Close()
		return 0, r.fail(start, SourceUI, "%w", err)
	}

	retireCtx, retireCancel := context.WithTimeout(ctx, r.retireTimeout)
	defer retireCancel()

	var retireWarning bool
	if err := r.dispatcher.ReplaceOutput(retireCtx, r.workerRunCtx, name, out); err != nil {
		if errors.Is(err, pipeline.ErrDispatcherStopped) {
			_ = out.Close()
			return 0, r.fail(start, SourceUI, "%w", err)
		}
		retireWarning = true
		r.logger.Warn("apply: old output retire timeout, replacement active", "output", name, "error", err)
	}

	if _, fileOwned := r.fileState[name]; fileOwned {
		r.fileState[name] = resolved
	}

	if _, fromFile := r.fileState[name]; !fromFile {
		r.apiState[name] = resolved
		r.apiVersions[name] = newVersion
		delete(r.apiFailed, name)
	}
	r.recordUI(start, retireWarning)
	return newVersion, nil
}

// RemoveOutput retires an output and deletes it from the database, even if it is not running.
// version is the stored version the caller read; with a database, any other returns ErrVersionConflict.
func (r *Reloader) RemoveOutput(ctx context.Context, name string, version int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrReloaderClosed
	}
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
	r.forgetAPIOutput(name)

	r.recordUI(start, retireWarning)
	return nil
}

// Reload applies the delta between the output files and the running file outputs, in the order of
// API writes: build, provision, then swap. A failed provision changes nothing and the next reload
// tries again. ctx bounds parse, Init and Provision; new workers run on workerRunCtx so they outlive ctx.
func (r *Reloader) Reload(ctx, workerRunCtx context.Context, retireTimeout time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrReloaderClosed
	}

	start := time.Now()

	outsCfg, err := config.LoadOutputs(r.outputPaths)
	if err != nil {
		return r.fail(start, SourceFile, "reload parse: %w", err)
	}
	if r.rejectInline {
		if err := config.CheckNoInlineSecrets(outsCfg.Outputs, r.catalog); err != nil {
			return r.fail(start, SourceFile, "reload secrets: %w", err)
		}
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

	// A new secret path whose file holds the same value changes nothing at runtime but must reach the store.
	rawChanged := !reflect.DeepEqual(r.fileRaw, outsCfg.Outputs)

	rotated, err := r.rotatedAPIOutputs(ctx, resolved)
	if err != nil {
		return r.fail(start, SourceFile, "reload: %w", err)
	}

	if diff.IsEmpty() && !rawChanged && len(rotated) == 0 {
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

	// A stored API output whose secret file changed is rebuilt; one that does not build keeps running as it was.
	rebuilt, rotationFailures := pipeline.BuildEach(ctx, r.catalog, rotated, r.runtimeDefaults, r.deps)
	for name, failure := range rotationFailures {
		r.logger.Warn("reload: stored output keeps its previous secret", "output", name, "error", failure)
	}
	maps.Copy(built, rebuilt)

	if r.database != nil {
		if err := r.database.Provision(ctx, &core.ProvisionRequest{Outputs: outsCfg.Outputs}); err != nil {
			closeOutputs(built)
			return r.fail(start, SourceFile, "reload provision: %w", databaseError(err))
		}
	}

	retireCtx, retireCancel := context.WithTimeout(ctx, retireTimeout)
	defer retireCancel()

	// retireWarning means a drain timed out but the replacement is live.
	var retireWarning bool
	if err := r.dispatcher.Apply(retireCtx, workerRunCtx, built, diff.Removed); err != nil {
		if errors.Is(err, pipeline.ErrDispatcherStopped) {
			closeOutputs(built)
			return r.fail(start, SourceFile, "reload abandoned: dispatcher stopped during apply")
		}
		retireWarning = true
		r.logger.Warn("reload: retire timeout, replacements active", "error", err)
	}

	r.fileState = resolved
	r.fileRaw = copyConfigs(outsCfg.Outputs)
	for name := range rebuilt {
		r.apiState[name] = rotated[name]
	}
	for name := range resolved {
		r.forgetAPIOutput(name)
	}
	duration := time.Since(start)

	if retireWarning {
		r.metrics.recordPartialSuccess(duration, SourceFile)
		r.logger.Warn("reload partial",
			"added", len(diff.Added),
			"changed", len(diff.Changed),
			"removed", len(diff.Removed),
			"rotated", len(rebuilt),
			"retire_warning", retireWarning,
			"duration", duration,
		)
	} else {
		r.metrics.recordSuccess(duration, SourceFile)
		r.logger.Info("reload complete",
			"added", len(diff.Added),
			"changed", len(diff.Changed),
			"removed", len(diff.Removed),
			"rotated", len(rebuilt),
			"duration", duration,
		)
	}
	return nil
}

func (r *Reloader) forgetAPIOutput(name string) {
	delete(r.apiState, name)
	delete(r.apiVersions, name)
	delete(r.apiFailed, name)
}

// Reconcile applies the API outputs other instances changed in the database: it starts, replaces or
// stops them without writing back. A change that does not build here leaves the previous output
// running, reported with the version it could not apply, and is tried again at the next reconcile.
// Outputs from files, and names the files define, are left to file reloads.
func (r *Reloader) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrReloaderClosed
	}
	if !r.bound {
		return ErrReloaderNotBound
	}
	if r.database == nil {
		return nil
	}
	entries, err := r.database.GetOutputConfigs(ctx)
	if err != nil {
		return databaseError(err)
	}

	resolved := make(map[string]map[string]any)
	versions := make(map[string]int64)
	failures := make(map[string]error)
	for name, entry := range entries {
		if _, fromFile := r.fileState[name]; fromFile || entry.Provisioned || r.apiVersions[name] == entry.Version {
			continue
		}
		versions[name] = entry.Version
		outputType, ok := r.catalog.Get(name)
		if !ok {
			failures[name] = fmt.Errorf("%w: %q", ErrUnknownOutputType, name)
			continue
		}
		cfg := utils.DeepCopyMap(entry.Config)
		if err := config.ResolveSecrets(name, cfg, outputType.Schema); err != nil {
			failures[name] = err
			continue
		}
		resolved[name] = cfg
	}
	var removed []string
	for _, known := range []map[string]int64{r.apiVersions, r.apiFailed} {
		for name := range known {
			// A row the files of another instance took over keeps running here until this instance's own files say so.
			if _, stored := entries[name]; !stored && !slices.Contains(removed, name) {
				removed = append(removed, name)
			}
		}
	}
	if len(resolved) == 0 && len(failures) == 0 && len(removed) == 0 {
		return nil
	}

	built, buildFailures := pipeline.BuildEach(ctx, r.catalog, resolved, r.runtimeDefaults, r.deps)
	maps.Copy(failures, buildFailures)
	if len(built) > 0 || len(removed) > 0 {
		retireCtx, cancel := context.WithTimeout(ctx, r.retireTimeout)
		defer cancel()
		if err := r.dispatcher.Apply(retireCtx, r.workerRunCtx, built, removed); err != nil {
			if errors.Is(err, pipeline.ErrDispatcherStopped) {
				closeOutputs(built)
				return err
			}
			r.logger.Warn("reconcile: retire timeout, replacements active", "error", err)
		}
	}
	for name := range built {
		r.apiState[name] = resolved[name]
		r.apiVersions[name] = versions[name]
		delete(r.apiFailed, name)
	}
	for _, name := range removed {
		r.forgetAPIOutput(name)
	}
	for name, failure := range failures {
		r.dispatcher.ReportUpdateFailure(name, fmt.Sprintf("version %d not applied: %v", versions[name], failure))
		if r.apiFailed[name] != versions[name] {
			r.logger.Warn("reconcile: stored output change not applied here", "output", name, "version", versions[name], "error", failure)
		}
		r.apiFailed[name] = versions[name]
	}
	if len(built) > 0 || len(removed) > 0 {
		r.logger.Info("reconcile: applied changes from the database", "applied", len(built), "removed", len(removed))
	}
	return nil
}

// rotatedAPIOutputs returns the running API outputs, not shadowed by a file output, whose secret files
// now read differently, resolved again from their stored config.
func (r *Reloader) rotatedAPIOutputs(ctx context.Context, fileOutputs map[string]map[string]any) (map[string]map[string]any, error) {
	if r.database == nil || len(r.apiState) == 0 {
		return nil, nil
	}
	entries, err := r.database.GetOutputConfigs(ctx)
	if err != nil {
		return nil, databaseError(err)
	}
	rotated := make(map[string]map[string]any)
	for name, running := range r.apiState {
		entry, stored := entries[name]
		// A new version is applied by Reconcile, which records it; here only the secret files changed.
		if _, fromFile := fileOutputs[name]; fromFile || !stored || entry.Version != r.apiVersions[name] {
			continue
		}
		outputType, ok := r.catalog.Get(name)
		if !ok {
			continue
		}
		cfg := utils.DeepCopyMap(entry.Config)
		if err := config.ResolveSecrets(name, cfg, outputType.Schema); err != nil {
			r.logger.Warn("reload: stored output keeps its previous secret", "output", name, "error", err)
			continue
		}
		if !reflect.DeepEqual(cfg, running) {
			rotated[name] = cfg
		}
	}
	return rotated, nil
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

func (r *Reloader) writeOutput(ctx context.Context, name string, version int64, cfg map[string]any) (int64, error) {
	if r.database == nil {
		return 0, nil
	}
	newVersion, err := r.database.SaveOutputConfig(ctx, name, version, cfg)
	return newVersion, databaseError(err)
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
