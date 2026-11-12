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
	"strings"
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

// ReloaderConfig holds the Reloader dependencies; contexts are passed to ReconcileFiles and BindWorkerContext.
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
	// StoredAPIOutputs are APIOutputs as stored, secret and File field files unresolved.
	StoredAPIOutputs map[string]map[string]any
	// InitialDigests and APIDigests are the FileDigests of InitialOutputs and APIOutputs, read before they were built so they describe
	// the files the running drivers read. An output without one is rebuilt once by the next reload.
	InitialDigests map[string]string
	APIDigests     map[string]string
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
	// apiState holds the running API outputs with resolved secrets, apiRaw the same as stored; resolving
	// apiRaw again and comparing with apiState shows a rotated secret file without reading the database.
	apiState map[string]map[string]any
	apiRaw   map[string]map[string]any
	// fileDigests and apiDigests hold, per running output, the fileFieldsDigest it was built with:
	// a renewed certificate is a change even though its path is not.
	fileDigests map[string]string
	apiDigests  map[string]string
	// apiVersions holds the stored version each running API output was built from, apiFailed the
	// version of each API output change that did not build here.
	apiVersions map[string]int64
	apiFailed   map[string]int64
	// rotationFailed holds the running API outputs whose status warns of a rotation that did not apply.
	rotationFailed map[string]bool
	// Snapshot keys of the input last applied, last rejected, and left pending by a transient failure.
	applied         string
	rejected        string
	pending         string
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

// NewReloader returns a Reloader with its own deep copies of InitialOutputs and FileOutputs. The
// digests in cfg are the base the next reload compares the File field files with.
func NewReloader(cfg *ReloaderConfig) *Reloader {
	r := &Reloader{
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
		apiRaw:          make(map[string]map[string]any, len(cfg.APIOutputs)),
		apiVersions:     copyVersions(cfg.APIVersions),
		apiFailed:       copyVersions(cfg.FailedAPIVersions),
		rotationFailed:  make(map[string]bool),
		rejectInline:    cfg.RejectInlineSecrets,
		logger:          cfg.Logger,
		fileDigests:     make(map[string]string),
		apiDigests:      make(map[string]string),
	}
	copyDigests(r.fileDigests, cfg.InitialDigests, r.fileState)
	copyDigests(r.apiDigests, cfg.APIDigests, r.apiState)
	copyRunningConfigs(r.apiRaw, cfg.StoredAPIOutputs, r.apiState)
	return r
}

// copyDigests copies the digests of the outputs in running from src into dst.
func copyDigests(dst, src map[string]string, running map[string]map[string]any) {
	for name, digest := range src {
		if _, ok := running[name]; ok {
			dst[name] = digest
		}
	}
}

func copyRunningConfigs(dst, src, running map[string]map[string]any) {
	for name, cfg := range src {
		if _, ok := running[name]; ok {
			dst[name] = utils.DeepCopyMap(cfg)
		}
	}
}

// FileDigests returns the digest of the File field files of each of configs, to be read before the outputs are built and passed to
// NewReloader. A config whose files cannot be read gets none, so the first reload that reads them rebuilds the output once.
func FileDigests(cat *catalog.Catalog, configs map[string]map[string]any) map[string]string {
	digests := make(map[string]string, len(configs))
	for name, cfg := range configs {
		if digest, err := digestOf(cat, name, cfg); err == nil {
			digests[name] = digest
		}
	}
	return digests
}

// digest returns the fileFieldsDigest of cfg for the schema of name; an unknown type has none.
func (r *Reloader) digest(name string, cfg map[string]any) (string, error) {
	return digestOf(r.catalog, name, cfg)
}

func digestOf(cat *catalog.Catalog, name string, cfg map[string]any) (string, error) {
	outputType, ok := cat.Get(name)
	if !ok {
		return "", nil
	}
	return fileFieldsDigest(name, cfg, outputType.Schema.Fields)
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

// FilePaths returns the files the file outputs read, as written in the output files at the last
// successful reload, sorted and without duplicates.
func (r *Reloader) FilePaths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var files []string
	for name, cfg := range r.fileRaw {
		outputType, ok := r.catalog.Get(name)
		if !ok {
			continue
		}
		paths := make(map[string]string)
		// A value that is not a path fails the build; the paths before it are still watched.
		_ = output.CollectFilePaths(cfg, outputType.Schema.Fields, paths)
		files = slices.AppendSeq(files, maps.Values(paths))
	}
	slices.Sort(files)
	return slices.Compact(files)
}

// ApplyOutput applies one UI-driven output config to the dispatcher and persists it, returning the stored version. version is the
// stored version cfg was built from, 0 for one not stored yet; with a database, any other stored version is core.ErrVersionConflict.
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
	// Read before the build, so a file renewed during it is seen by the next reload.
	digest, err := fileFieldsDigest(name, resolved, outputType.Schema.Fields)
	if err != nil {
		return 0, r.fail(start, SourceUI, "apply files: %w: %w", pipeline.ErrInvalidOutputConfig, err)
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
		// The running set no longer matches the last applied files.
		r.applied = ""
		r.fileState[name] = resolved
		r.fileDigests[name] = digest
	} else {
		r.apiState[name] = resolved
		r.apiRaw[name] = stored
		r.apiDigests[name] = digest
		r.apiVersions[name] = newVersion
		delete(r.apiFailed, name)
		delete(r.rotationFailed, name)
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
	if _, fileOwned := r.fileState[name]; fileOwned {
		r.applied = ""
	}
	delete(r.fileState, name)
	delete(r.fileDigests, name)
	r.forgetAPIOutput(name)

	r.recordUI(start, retireWarning)
	return nil
}

// Trigger says what asks for a file reconcile.
type Trigger int

const (
	// TriggerChange is a change the watcher or the poller saw.
	TriggerChange Trigger = iota
	// TriggerRetry retries the input a transient failure left pending.
	TriggerRetry
	// TriggerForce attempts the input even if it was applied or rejected before, as SIGHUP does.
	TriggerForce
)

// Outcome is what a file reconcile did.
type Outcome int

const (
	// OutcomeSkipped means the input was already applied, rejected or waiting for its retry; nothing was recorded.
	OutcomeSkipped Outcome = iota
	// OutcomeApplied means the input is active; a retire timeout or a rotation that did not build is reported.
	OutcomeApplied
	// OutcomeRejected means the input is invalid; it is attempted again when it changes or when forced.
	OutcomeRejected
	// OutcomeRetry means the database was unavailable; the input stays pending.
	OutcomeRetry
	// OutcomeStopped means the reloader, the dispatcher or the context is shutting down.
	OutcomeStopped
)

// ReconcileFiles applies the delta between the output files and the running file outputs: build,
// provision, then swap. The input read is keyed; a key already applied or rejected is skipped unless
// trigger is TriggerForce, and one a transient failure left pending waits for TriggerRetry. ctx
// bounds parse, Init and Provision; new workers run on workerRunCtx and outlive ctx.
func (r *Reloader) ReconcileFiles(ctx, workerRunCtx context.Context, retireTimeout time.Duration, trigger Trigger) (Outcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return OutcomeStopped, ErrReloaderClosed
	}

	start := time.Now()
	snap := newSnapshot()
	snap.addFiles(r.outputPaths)

	outsCfg, resolved, digests, err := r.loadFiles()
	if err != nil {
		snap.add(err.Error())
		key := snap.key()
		return r.inputFailed(ctx, start, trigger, key, key, err)
	}
	for _, name := range slices.Sorted(maps.Keys(resolved)) {
		snap.add(name, resolved[name], digests[name])
	}
	filesKey := snap.key()
	if trigger == TriggerChange && filesKey == r.pending {
		return OutcomeSkipped, nil
	}

	rotated, rotatedDigests, rotationFailures := r.rotatedAPIOutputs(resolved, snap)
	key := snap.key()
	if trigger != TriggerForce {
		switch key {
		case r.applied:
			r.rejected, r.pending = "", ""
			return OutcomeSkipped, nil
		case r.rejected:
			r.pending = ""
			return OutcomeSkipped, nil
		}
	}

	diff := r.fileDiff(resolved, digests)
	// A new secret path whose file holds the same value changes nothing at runtime but must reach the store.
	rawChanged := !reflect.DeepEqual(r.fileRaw, outsCfg.Outputs)

	if diff.IsEmpty() && !rawChanged && len(rotated) == 0 {
		if len(rotationFailures) > 0 {
			return r.rotationRejected(ctx, start, trigger, filesKey, key, rotationFailures)
		}
		r.logger.Debug("reload: no output config changes detected")
		r.metrics.recordNoop(SourceFile)
		r.applied, r.rejected, r.pending = key, "", ""
		return OutcomeApplied, nil
	}

	// One concurrent build of every added and changed output; a failure leaves the running set untouched.
	toBuild := make(map[string]map[string]any, len(diff.Added)+len(diff.Changed))
	maps.Copy(toBuild, diff.Added)
	maps.Copy(toBuild, diff.Changed)
	built, err := r.createOutputs(ctx, toBuild)
	if err != nil {
		return r.inputFailed(ctx, start, trigger, filesKey, key, fmt.Errorf("reload create: %w", err))
	}

	// A stored API output whose secret file changed is rebuilt; one that does not build keeps running as it was.
	rebuilt, buildFailures := pipeline.BuildEach(ctx, r.catalog, rotated, r.runtimeDefaults, r.deps)
	for name, failure := range buildFailures {
		rotationFailures[name] = fmt.Errorf("output %q: %w", name, failure)
	}
	if diff.IsEmpty() && !rawChanged && len(rebuilt) == 0 {
		return r.rotationRejected(ctx, start, trigger, filesKey, key, rotationFailures)
	}
	maps.Copy(built, rebuilt)

	if r.database != nil {
		if err := r.database.Provision(ctx, &core.ProvisionRequest{Outputs: outsCfg.Outputs}); err != nil {
			closeOutputs(built)
			return r.inputFailed(ctx, start, trigger, filesKey, key, fmt.Errorf("reload provision: %w", databaseError(err)))
		}
	}

	retireCtx, retireCancel := context.WithTimeout(ctx, retireTimeout)
	defer retireCancel()

	// retireWarning means a drain timed out but the replacement is live.
	var retireWarning bool
	if err := r.dispatcher.Apply(retireCtx, workerRunCtx, built, diff.Removed); err != nil {
		if errors.Is(err, pipeline.ErrDispatcherStopped) {
			closeOutputs(built)
			return r.inputFailed(ctx, start, trigger, filesKey, key, fmt.Errorf("reload abandoned: %w", err))
		}
		retireWarning = true
		r.logger.Warn("reload: retire timeout, replacements active", "error", err)
	}

	r.fileState = resolved
	r.fileDigests = digests
	r.fileRaw = copyConfigs(outsCfg.Outputs)
	for name := range rebuilt {
		r.apiState[name] = rotated[name]
		r.apiDigests[name] = rotatedDigests[name]
		delete(r.rotationFailed, name)
	}
	for name := range resolved {
		r.forgetAPIOutput(name)
	}
	r.reportRotationFailures(rotationFailures)
	duration := time.Since(start)

	switch {
	case len(rotationFailures) > 0, retireWarning:
		// A retire timeout leaves the replacements active, so the input is applied; a failed rotation is rejected.
		if len(rotationFailures) > 0 {
			r.applied, r.rejected = "", key
		} else {
			r.applied, r.rejected = key, ""
		}
		r.pending = ""
		r.metrics.recordPartialSuccess(duration, SourceFile)
		r.logger.Warn("reload partial",
			"added", len(diff.Added),
			"changed", len(diff.Changed),
			"removed", len(diff.Removed),
			"rotated", len(rebuilt),
			"rotation_failed", len(rotationFailures),
			"retire_warning", retireWarning,
			"duration", duration,
		)
	default:
		r.applied, r.rejected, r.pending = key, "", ""
		r.metrics.recordSuccess(duration, SourceFile)
		r.logger.Info("reload complete",
			"added", len(diff.Added),
			"changed", len(diff.Changed),
			"removed", len(diff.Removed),
			"rotated", len(rebuilt),
			"duration", duration,
		)
	}
	return OutcomeApplied, nil
}

// fileDiff returns the delta from the running file outputs to resolved; changed File field files and
// a name already running from the API count as changes.
func (r *Reloader) fileDiff(resolved map[string]map[string]any, digests map[string]string) DiffResult {
	diff := DiffOutputConfigs(r.fileState, resolved)
	for name, cfg := range resolved {
		_, running := r.fileState[name]
		if _, changed := diff.Changed[name]; running && !changed && digests[name] != r.fileDigests[name] {
			diff.Changed[name] = cfg
		}
	}
	for _, name := range r.dispatcher.OutputNames() {
		if cfg, added := diff.Added[name]; added {
			diff.Changed[name] = cfg
			delete(diff.Added, name)
		}
	}
	return diff
}

// loadFiles parses the output files and resolves their secret and File field files, so a rotated
// file is a change; the database gets the configs as written.
func (r *Reloader) loadFiles() (outsCfg *config.OutputsConfig, resolved map[string]map[string]any, digests map[string]string, err error) {
	outsCfg, err = config.LoadOutputs(r.outputPaths)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reload parse: %w", err)
	}
	if r.rejectInline {
		if err := config.CheckNoInlineSecrets(outsCfg.Outputs, r.catalog); err != nil {
			return nil, nil, nil, fmt.Errorf("reload secrets: %w", err)
		}
	}
	resolved, err = config.ResolvedOutputs(outsCfg.Outputs, r.catalog)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reload secrets: %w", err)
	}
	digests = make(map[string]string, len(resolved))
	for _, name := range slices.Sorted(maps.Keys(resolved)) {
		digest, err := r.digest(name, resolved[name])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reload files: %w", err)
		}
		digests[name] = digest
	}
	return outsCfg, resolved, digests, nil
}

// inputFailed records a failed file reconcile: a database failure leaves filesKey pending, a shutdown
// records nothing, any other failure rejects key.
func (r *Reloader) inputFailed(ctx context.Context, start time.Time, trigger Trigger, filesKey, key string, err error) (Outcome, error) {
	switch {
	case ctx.Err() != nil, errors.Is(err, pipeline.ErrDispatcherStopped):
		r.metrics.recordFailure(time.Since(start), SourceFile)
		return OutcomeStopped, err
	case errors.Is(err, ErrDatabaseUnavailable):
		r.pending, r.rejected = filesKey, ""
		r.metrics.recordFailure(time.Since(start), SourceFile)
		return OutcomeRetry, err
	case trigger != TriggerForce && key == r.rejected:
		r.pending = ""
		return OutcomeSkipped, nil
	}
	r.rejected, r.pending = key, ""
	r.metrics.recordFailure(time.Since(start), SourceFile)
	return OutcomeRejected, err
}

// rotationRejected records a reconcile whose only changes were secret rotations that did not apply.
func (r *Reloader) rotationRejected(
	ctx context.Context, start time.Time, trigger Trigger, filesKey, key string, failures map[string]error,
) (Outcome, error) {
	r.reportRotationFailures(failures)
	messages := make([]string, 0, len(failures))
	for _, name := range slices.Sorted(maps.Keys(failures)) {
		messages = append(messages, failures[name].Error())
	}
	return r.inputFailed(ctx, start, trigger, filesKey, key,
		fmt.Errorf("reload: secret rotation not applied: %s", strings.Join(messages, "; ")))
}

// reportRotationFailures warns each output of its failed rotation; it keeps running with its previous secret.
func (r *Reloader) reportRotationFailures(failures map[string]error) {
	for _, name := range slices.Sorted(maps.Keys(failures)) {
		r.logger.Warn("reload: stored output keeps its previous secret", "output", name, "error", failures[name])
		r.dispatcher.ReportUpdateFailure(name, pipeline.WarningRotation, "secret rotation not applied: "+failures[name].Error())
		r.rotationFailed[name] = true
	}
}

func (r *Reloader) forgetAPIOutput(name string) {
	delete(r.apiState, name)
	delete(r.apiRaw, name)
	delete(r.apiDigests, name)
	delete(r.apiVersions, name)
	delete(r.apiFailed, name)
	delete(r.rotationFailed, name)
}

// Reconcile starts, replaces or stops the API outputs other instances changed in the database, without writing back; names the files
// define are left to file reloads. A change that does not build keeps the previous output running, reports its version and is retried next time.
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
	start := time.Now()
	entries, err := r.database.GetOutputConfigs(ctx)
	if err != nil {
		return r.fail(start, SourceReplica, "%w", databaseError(err))
	}

	resolved := make(map[string]map[string]any)
	digests := make(map[string]string)
	versions := make(map[string]int64)
	failures := make(map[string]error)
	for name, entry := range entries {
		if _, fromFile := r.fileState[name]; fromFile || entry.Provisioned || r.apiVersions[name] == entry.Version {
			continue
		}
		versions[name] = entry.Version
		cfg, digest, err := r.resolveStored(name, entry.Config)
		if err != nil {
			failures[name] = err
			continue
		}
		resolved[name] = cfg
		digests[name] = digest
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
		r.metrics.recordNoop(SourceReplica)
		return nil
	}

	var retireWarning bool
	built, buildFailures := pipeline.BuildEach(ctx, r.catalog, resolved, r.runtimeDefaults, r.deps)
	maps.Copy(failures, buildFailures)
	if len(built) > 0 || len(removed) > 0 {
		retireCtx, cancel := context.WithTimeout(ctx, r.retireTimeout)
		defer cancel()
		if err := r.dispatcher.Apply(retireCtx, r.workerRunCtx, built, removed); err != nil {
			if errors.Is(err, pipeline.ErrDispatcherStopped) {
				closeOutputs(built)
				return r.fail(start, SourceReplica, "%w", err)
			}
			retireWarning = true
			r.logger.Warn("reconcile: retire timeout, replacements active", "error", err)
		}
	}
	for name := range built {
		r.apiState[name] = resolved[name]
		r.apiRaw[name] = entries[name].Config
		r.apiDigests[name] = digests[name]
		r.apiVersions[name] = versions[name]
		delete(r.apiFailed, name)
		delete(r.rotationFailed, name)
	}
	for _, name := range removed {
		r.forgetAPIOutput(name)
	}
	for name, failure := range failures {
		// Forget the rotation so a later rotation check does not clear the version warning.
		delete(r.rotationFailed, name)
		r.dispatcher.ReportUpdateFailure(name, pipeline.WarningUpdate, fmt.Sprintf("version %d not applied: %v", versions[name], failure))
		if r.apiFailed[name] != versions[name] {
			r.logger.Warn("reconcile: stored output change not applied here", "output", name, "version", versions[name], "error", failure)
		}
		r.apiFailed[name] = versions[name]
	}
	if len(built) > 0 || len(removed) > 0 {
		r.logger.Info("reconcile: applied changes from the database", "applied", len(built), "removed", len(removed))
	}
	switch {
	case len(failures) > 0:
		r.metrics.recordFailure(time.Since(start), SourceReplica)
	case retireWarning:
		r.metrics.recordPartialSuccess(time.Since(start), SourceReplica)
	default:
		r.metrics.recordSuccess(time.Since(start), SourceReplica)
	}
	return nil
}

// resolveStored returns a copy of the stored config of name with its secret files read, and the
// digest of its File field files.
func (r *Reloader) resolveStored(name string, stored map[string]any) (cfg map[string]any, digest string, err error) {
	outputType, ok := r.catalog.Get(name)
	if !ok {
		return nil, "", fmt.Errorf("%w: %q", ErrUnknownOutputType, name)
	}
	cfg = utils.DeepCopyMap(stored)
	if err := config.ResolveSecrets(name, cfg, outputType.Schema); err != nil {
		return nil, "", err
	}
	digest, err = fileFieldsDigest(name, cfg, outputType.Schema.Fields)
	if err != nil {
		return nil, "", err
	}
	return cfg, digest, nil
}

// rotatedAPIOutputs returns the running API outputs, not shadowed by a file output, whose secret files
// or File field files read differently, resolved again from their stored config, with their digests and
// the failure of each whose files cannot be read; what it reads is added to snap.
func (r *Reloader) rotatedAPIOutputs(
	fileOutputs map[string]map[string]any, snap *snapshot,
) (rotated map[string]map[string]any, digests map[string]string, failures map[string]error) {
	rotated = make(map[string]map[string]any)
	digests = make(map[string]string)
	failures = make(map[string]error)
	for _, name := range slices.Sorted(maps.Keys(r.apiState)) {
		stored, ok := r.apiRaw[name]
		if _, fromFile := fileOutputs[name]; fromFile || !ok {
			continue
		}
		outputType, ok := r.catalog.Get(name)
		if !ok {
			continue
		}
		snap.add(name, r.apiVersions[name])
		cfg := utils.DeepCopyMap(stored)
		if err := config.ResolveSecrets(name, cfg, outputType.Schema); err != nil {
			snap.add(err.Error())
			failures[name] = err
			continue
		}
		digest, err := fileFieldsDigest(name, cfg, outputType.Schema.Fields)
		if err != nil {
			snap.add(err.Error())
			failures[name] = err
			continue
		}
		snap.add(cfg, digest)
		if !reflect.DeepEqual(cfg, r.apiState[name]) || digest != r.apiDigests[name] {
			rotated[name] = cfg
			digests[name] = digest
			continue
		}
		// The files match the running output again, so its rotation warning is stale.
		if r.rotationFailed[name] {
			delete(r.rotationFailed, name)
			r.dispatcher.ClearUpdateFailure(name)
		}
	}
	return rotated, digests, failures
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
