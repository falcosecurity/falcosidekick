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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/inmemory"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

// flakyDB fails every read and write while down, as an unreachable postgres does, and counts the reads.
type flakyDB struct {
	core.Database
	down  atomic.Bool
	reads atomic.Int32
}

var errConnectionRefused = errors.New("connect to postgres: connection refused")

func (d *flakyDB) Provision(ctx context.Context, req *core.ProvisionRequest) error {
	if d.down.Load() {
		return errConnectionRefused
	}
	return d.Database.Provision(ctx, req)
}

func (d *flakyDB) GetOutputConfigs(ctx context.Context) (map[string]*core.OutputConfigEntry, error) {
	d.reads.Add(1)
	if d.down.Load() {
		return nil, errConnectionRefused
	}
	return d.Database.GetOutputConfigs(ctx)
}

// fileHarness runs the coordinator, the watcher loop on fake events and, when poll is set, the poller on one Reloader.
type fileHarness struct {
	r      *Reloader
	env    *reloaderTestEnv
	reg    *prometheus.Registry
	events chan fsnotify.Event
	path   string
}

func startFileHarness(t *testing.T, path string, db core.Database, poll time.Duration) *fileHarness {
	t.Helper()
	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	reg := prometheus.NewRegistry()
	cfg := &ReloaderConfig{
		OutputPaths: []string{path}, Catalog: cat, Dispatcher: env.d, Registry: reg,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
		InitialOutputs: map[string]map[string]any{}, FileOutputs: map[string]map[string]any{},
	}
	if db != nil {
		cfg.Database = db
	}
	r := NewReloader(cfg)
	r.BindWorkerContext(env.workerRunCtx, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
		env.shutdown(t)
	})
	c := NewCoordinator(func(ctx context.Context, trigger Trigger) (Outcome, error) {
		return r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, trigger)
	}, slog.Default())
	c.jitter = func() float64 { return 0.5 }
	wg.Go(func() { c.Run(ctx) })

	h := &fileHarness{r: r, env: env, reg: reg, events: make(chan fsnotify.Event), path: path}
	w := NewWatcher([]string{path}, nil, testDebounce, c.Notify, slog.Default())
	fs := &fakeDirWatcher{}
	w.syncDirs(fs)
	w.resolveTargets()
	wg.Go(func() { _ = w.loop(ctx, fs, h.events, make(chan error)) })
	if poll > 0 {
		p := NewPoller([]string{path}, nil, poll, c.Notify, slog.Default())
		wg.Go(func() { _ = p.Run(ctx) })
	}
	synctest.Wait()
	return h
}

// write changes the output file and reports it as fsnotify does.
func (h *fileHarness) write(t *testing.T, content string) {
	t.Helper()
	writeOutputsYAML(t, h.path, content)
	h.events <- fsnotify.Event{Name: h.path, Op: fsnotify.Write}
}

func (h *fileHarness) reloads(t *testing.T, result string) float64 {
	t.Helper()
	gathered, err := h.reg.Gather()
	require.NoError(t, err)
	return sumReloads(gathered, result, SourceFile)
}

func TestCoordinatedTriggersMakeOneAttemptPerChange(t *testing.T) {
	tests := []struct {
		name    string
		content string
		result  string
		running []string
	}{
		{name: "valid change", content: "outputs:\n  slack: {}\n", result: resultSuccess, running: []string{"slack"}},
		{name: "invalid file", content: "outputs:\n  slack: [\n", result: resultFailure, running: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outputs.yaml")
			writeOutputsYAML(t, path, "outputs: {}\n")
			synctest.Test(t, func(t *testing.T) {
				h := startFileHarness(t, path, nil, time.Second)

				h.write(t, tt.content)
				time.Sleep(5 * time.Second)
				synctest.Wait()
				assert.Equal(t, 1.0, h.reloads(t, metricReloadTotal), "one attempt over the watcher and five poller ticks")
				assert.Equal(t, 1.0, h.reloads(t, tt.result))
				assert.ElementsMatch(t, tt.running, h.env.d.OutputNames())
			})
		})
	}
}

// The retry timer alone applies it: no SIGHUP, no other edit.
func TestCoordinatedReloadAppliesAPendingChangeWhenTheDatabaseReturns(t *testing.T) {
	for _, poll := range []time.Duration{0, time.Second} {
		t.Run(fmt.Sprintf("poll %s", poll), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outputs.yaml")
			writeOutputsYAML(t, path, "outputs: {}\n")
			synctest.Test(t, func(t *testing.T) {
				db := &flakyDB{Database: database.NewMemory()}
				db.down.Store(true)
				h := startFileHarness(t, path, db, poll)

				h.write(t, "outputs:\n  slack: {}\n")
				time.Sleep(3 * time.Second)
				synctest.Wait()
				assert.Equal(t, 1.0, h.reloads(t, resultFailure), "the poller does not attempt the pending change again")
				assert.Empty(t, h.env.d.OutputNames(), "nothing switched")

				db.down.Store(false)
				time.Sleep(5 * time.Second)
				synctest.Wait()
				assert.Equal(t, []string{"slack"}, h.env.d.OutputNames(), "the retry applies the change")
				assert.Equal(t, 1.0, h.reloads(t, resultSuccess))
				assert.Equal(t, 1.0, h.reloads(t, resultFailure))

				time.Sleep(time.Minute)
				synctest.Wait()
				assert.Equal(t, 2.0, h.reloads(t, metricReloadTotal), "nothing more once applied")
			})
		})
	}
}

func TestCoordinatedReloadSkipsAnUnchangedInputWhileTheDatabaseIsDown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outputs.yaml")
	writeOutputsYAML(t, path, "outputs: {}\n")
	synctest.Test(t, func(t *testing.T) {
		db := &flakyDB{Database: database.NewMemory()}
		h := startFileHarness(t, path, db, time.Second)
		_, err := h.r.ApplyOutput(context.Background(), "slack", 0, map[string]any{})
		require.NoError(t, err)
		db.down.Store(true)

		h.write(t, "outputs: {}\n")
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, 0.0, h.reloads(t, resultFailure), "an unchanged input is never attempted")
		assert.Equal(t, 1.0, h.reloads(t, resultNoop), "the first attempt reads the files and records them")
		assert.Equal(t, []string{"slack"}, h.env.d.OutputNames())
	})
}

func TestReconcileFilesRejectsAnInvalidInputOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outputs.yaml")
	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	reg := prometheus.NewRegistry()
	r := NewReloader(&ReloaderConfig{
		OutputPaths: []string{path}, Catalog: cat, Dispatcher: env.d, Registry: reg,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	ctx := t.Context()
	attempt := func(trigger Trigger) Outcome {
		outcome, _ := r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, trigger)
		return outcome
	}
	failures := func() float64 {
		gathered, err := reg.Gather()
		require.NoError(t, err)
		return getMetricValue(gathered, metricReloadFailures)
	}

	writeOutputsYAML(t, path, "outputs:\n  slack: [\n")
	assert.Equal(t, OutcomeRejected, attempt(TriggerChange))
	assert.Equal(t, OutcomeSkipped, attempt(TriggerChange), "the same input is not attempted again")
	assert.Equal(t, OutcomeSkipped, attempt(TriggerRetry))
	assert.Equal(t, 1.0, failures())

	assert.Equal(t, OutcomeRejected, attempt(TriggerForce), "SIGHUP attempts it again")
	assert.Equal(t, 2.0, failures())

	writeOutputsYAML(t, path, "outputs:\n  slack: [ \n")
	assert.Equal(t, OutcomeRejected, attempt(TriggerChange), "another invalid input is a change")
	assert.Equal(t, 3.0, failures())

	writeOutputsYAML(t, path, "outputs:\n  slack: {}\n")
	assert.Equal(t, OutcomeApplied, attempt(TriggerChange))
	assert.Equal(t, OutcomeSkipped, attempt(TriggerChange))

	writeOutputsYAML(t, path, "outputs:\n  slack: [\n")
	assert.Equal(t, OutcomeRejected, attempt(TriggerChange), "an input rejected before an apply is a change again")
	assert.Equal(t, 4.0, failures())
	assert.Equal(t, []string{"slack"}, env.d.OutputNames(), "the applied input stays active")
}

// The integer 0 is "0s": accepted where the field allows it, refused with the range where a minimum applies.
func TestReconcileFilesReadsAZeroDurationAsTheAPIDoes(t *testing.T) {
	runtimeType := output.Type{
		Name:   "webhook",
		Schema: output.Schema{Fields: shared.BatchRuntimeConfigSchemaFields()},
		New: func(raw map[string]any, _ output.Deps) (output.Driver, error) {
			var cfg struct {
				Runtime output.RuntimeConfig `mapstructure:"runtime"`
			}
			if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
				return nil, err
			}
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}
	const webhookRuntime = "outputs:\n  webhook:\n    runtime:\n"
	for _, tt := range []struct {
		name, file, want string
	}{
		{name: "integer zero interval", file: webhookRuntime + "      retry:\n        initial_interval: 0\n",
			want: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "zero text interval", file: webhookRuntime + "      retry:\n        initial_interval: \"0s\"\n",
			want: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "integer zero max interval", file: webhookRuntime + "      retry:\n        max_interval: 0\n",
			want: "runtime.retry.max_interval: must be a duration between 1ms and 1h"},
		{name: "integer zero reset timeout", file: webhookRuntime + "      circuit_breaker:\n        reset_timeout: 0\n",
			want: "runtime.circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
		{name: "integer zero flush interval", file: webhookRuntime + "      batching:\n        flush_interval: 0\n",
			want: "runtime.batching.flush_interval: must be a duration between 10ms and 1h"},
		{name: "integer zero ttl is no expiry", file: "outputs:\n  inmemory:\n    capacity: 10\n    ttl: 0\n"},
		{name: "zero text ttl is no expiry", file: "outputs:\n  inmemory:\n    capacity: 10\n    ttl: \"0s\"\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outputs.yaml")
			writeOutputsYAML(t, path, tt.file)
			cat, err := catalog.New([]output.Type{runtimeType, inmemory.OutputType})
			require.NoError(t, err)
			env := newReloaderTestEnv(t, nil)
			defer env.shutdown(t)
			r := newFileReloader(t, env, cat, path, map[string]map[string]any{})

			outcome, err := r.ReconcileFiles(t.Context(), env.workerRunCtx, time.Second, TriggerChange)
			if tt.want != "" {
				assert.Equal(t, OutcomeRejected, outcome)
				require.ErrorContains(t, err, tt.want)
				assert.Empty(t, env.d.OutputNames(), "nothing is applied")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, OutcomeApplied, outcome)
			assert.Equal(t, []string{"inmemory"}, env.d.OutputNames())
		})
	}
}

func TestReconcileFilesNeverAcknowledgesAChangeMadeDuringTheAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    host: a\n")
	var once sync.Once
	typ := stubOutputType("slack", nil)
	typ.New = func(_ map[string]any, _ output.Deps) (output.Driver, error) {
		once.Do(func() { writeOutputsYAML(t, path, "outputs:\n  slack:\n    host: b\n") })
		return &testutil.MockDriver{DriverName: "slack"}, nil
	}
	cat, err := catalog.New([]output.Type{typ})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	r := newFileReloader(t, env, cat, path, map[string]map[string]any{})
	ctx := t.Context()

	outcome, err := r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerChange)
	require.NoError(t, err)
	assert.Equal(t, OutcomeApplied, outcome)
	assert.Equal(t, "a", r.fileState["slack"]["host"])

	outcome, err = r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerChange)
	require.NoError(t, err)
	assert.Equal(t, OutcomeApplied, outcome, "the content written during the build is not taken as applied")
	assert.Equal(t, "b", r.fileState["slack"]["host"])

	outcome, err = r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerChange)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSkipped, outcome)
}

func outputStatus(t *testing.T, d *pipeline.Dispatcher, name string) pipeline.OutputStatus {
	t.Helper()
	statuses := d.CollectStatus()
	for i := range statuses {
		if statuses[i].Name == name {
			return statuses[i]
		}
	}
	t.Fatalf("output %q has no status", name)
	return pipeline.OutputStatus{}
}

// The output keeps its previous secret and the rotation applies once the file is back.
func TestReconcileFilesRecordsAFailedSecretRotation(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(secret, []byte("first"), 0o600))
	var mu sync.Mutex
	var seen []string
	secretType := stubOutputType("slack", nil)
	secretType.Schema.Fields = []output.SchemaField{{Name: "token", Type: "string", Secret: true}}
	secretType.New = func(cfg map[string]any, _ output.Deps) (output.Driver, error) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, fmt.Sprint(cfg["token"]))
		return &testutil.MockDriver{DriverName: "slack"}, nil
	}
	cat, err := catalog.New([]output.Type{secretType, stubOutputType("teams", nil)})
	require.NoError(t, err)
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs: {}\n")
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	reg := prometheus.NewRegistry()
	r := NewReloader(&ReloaderConfig{
		OutputPaths: []string{path}, Catalog: cat, Dispatcher: env.d, Database: database.NewMemory(), Registry: reg,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)
	ctx := t.Context()
	_, err = r.ApplyOutput(ctx, "slack", 0, map[string]any{"token_file": secret})
	require.NoError(t, err)
	attempt := func() (Outcome, error) { return r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerChange) }
	reloads := func(result string) float64 {
		gathered, err := reg.Gather()
		require.NoError(t, err)
		return sumReloads(gathered, result, SourceFile)
	}

	require.NoError(t, os.Remove(secret))
	outcome, err := attempt()
	assert.Equal(t, OutcomeRejected, outcome)
	require.ErrorContains(t, err, "secret rotation not applied")
	assert.NotContains(t, err.Error(), secret, "the error names the field, not the path")
	assert.Equal(t, 1.0, reloads(resultFailure))
	assert.Equal(t, 0.0, reloads(resultNoop)+reloads(resultSuccess), "never success or noop over a failed rotation")
	status := outputStatus(t, env.d, "slack")
	assert.Contains(t, status.LastWarning, "secret rotation not applied")
	assert.Equal(t, pipeline.WarningRotation, status.WarningKind)
	assert.NotContains(t, status.LastWarning, secret, "the warning names the field, not the path")
	assert.NotContains(t, status.LastWarning, dir)
	assert.Equal(t, pipeline.HealthDegraded, status.Status)
	assert.Equal(t, []string{"first"}, seen, "the running output keeps its previous secret")

	outcome, err = attempt()
	require.NoError(t, err)
	assert.Equal(t, OutcomeSkipped, outcome, "the same failed rotation is not recorded again")
	assert.Equal(t, 1.0, reloads(resultFailure))

	writeOutputsYAML(t, path, "outputs:\n  teams: {}\n")
	outcome, err = attempt()
	require.NoError(t, err)
	assert.Equal(t, OutcomeApplied, outcome)
	assert.Equal(t, 1.0, reloads(resultPartial), "a file change applied beside a failed rotation is partial")
	assert.ElementsMatch(t, []string{"slack", "teams"}, env.d.OutputNames())
	assert.Empty(t, outputStatus(t, env.d, "teams").LastWarning, "only the output whose rotation failed warns")
	assert.Contains(t, outputStatus(t, env.d, "slack").LastWarning, "secret rotation not applied")

	require.NoError(t, os.WriteFile(secret, []byte("rotated"), 0o600))
	outcome, err = attempt()
	require.NoError(t, err)
	assert.Equal(t, OutcomeApplied, outcome)
	assert.Equal(t, []string{"first", "rotated"}, seen)
	assert.Empty(t, outputStatus(t, env.d, "slack").LastWarning, "the rebuilt output has no warning")
	assert.Equal(t, 1.0, reloads(resultSuccess))
}

func TestFailedRotationReasonsNeverHoldTheSecretPathOrValue(t *testing.T) {
	tests := []struct {
		breakFile func(t *testing.T, secret string)
		name      string
	}{
		{name: "missing", breakFile: func(t *testing.T, secret string) { require.NoError(t, os.Remove(secret)) }},
		{name: "too large", breakFile: func(t *testing.T, secret string) {
			require.NoError(t, os.WriteFile(secret, bytes.Repeat([]byte("s3cr3t-"), 200_000), 0o600))
		}},
		{name: "directory", breakFile: func(t *testing.T, secret string) {
			require.NoError(t, os.Remove(secret))
			require.NoError(t, os.Mkdir(secret, 0o700))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newRotationHarness(t, database.NewMemory())
			tt.breakFile(t, h.secret)
			outcome, err := h.attempt(TriggerChange)
			assert.Equal(t, OutcomeRejected, outcome)
			require.Error(t, err)
			warning := outputStatus(t, h.env.d, "slack").LastWarning
			require.NotEmpty(t, warning)
			for _, reason := range []string{err.Error(), warning} {
				assert.NotContains(t, reason, h.secret)
				assert.NotContains(t, reason, filepath.Dir(h.secret))
				assert.NotContains(t, reason, "s3cr3t")
				assert.NotContains(t, reason, "first")
			}
		})
	}
}

// The warning clears without a rebuild.
func TestAFailedRotationWarningClearsWhenTheSecretReadsAsRunning(t *testing.T) {
	h := newRotationHarness(t, database.NewMemory())
	require.NoError(t, os.Remove(h.secret))
	outcome, _ := h.attempt(TriggerChange)
	require.Equal(t, OutcomeRejected, outcome)
	require.NotEmpty(t, outputStatus(t, h.env.d, "slack").LastWarning)

	require.NoError(t, os.WriteFile(h.secret, []byte("first"), 0o600))
	outcome, err := h.attempt(TriggerChange)
	require.NoError(t, err)
	assert.Equal(t, OutcomeApplied, outcome)
	status := outputStatus(t, h.env.d, "slack")
	assert.Empty(t, status.LastWarning)
	assert.Equal(t, pipeline.HealthIdle, status.Status, "back to its normal state")
	assert.Equal(t, int32(1), h.builds.Load(), "nothing rebuilt")
}

type rotationHarness struct {
	r      *Reloader
	env    *reloaderTestEnv
	reg    *prometheus.Registry
	ctx    context.Context
	secret string
	builds atomic.Int32
}

// newRotationHarness runs a stored API output slack whose token comes from a secret file holding "first".
func newRotationHarness(t *testing.T, db core.Database) *rotationHarness {
	t.Helper()
	dir := t.TempDir()
	h := &rotationHarness{secret: filepath.Join(dir, "token"), ctx: t.Context(), reg: prometheus.NewRegistry()}
	require.NoError(t, os.WriteFile(h.secret, []byte("first"), 0o600))
	typ := stubOutputType("slack", nil)
	typ.Schema.Fields = []output.SchemaField{{Name: "token", Type: "string", Secret: true}}
	typ.New = func(_ map[string]any, _ output.Deps) (output.Driver, error) {
		h.builds.Add(1)
		return &testutil.MockDriver{DriverName: "slack"}, nil
	}
	cat, err := catalog.New([]output.Type{typ})
	require.NoError(t, err)
	h.env = newReloaderTestEnv(t, nil)
	t.Cleanup(func() { h.env.shutdown(t) })
	h.r = NewReloader(&ReloaderConfig{
		Catalog: cat, Dispatcher: h.env.d, Database: db, Registry: h.reg,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	h.r.BindWorkerContext(h.env.workerRunCtx, time.Second)
	_, err = h.r.ApplyOutput(h.ctx, "slack", 0, map[string]any{"token_file": h.secret})
	require.NoError(t, err)
	return h
}

func (h *rotationHarness) attempt(trigger Trigger) (Outcome, error) {
	return h.r.ReconcileFiles(h.ctx, h.env.workerRunCtx, time.Second, trigger)
}

func (h *rotationHarness) reloads(t *testing.T, result string) float64 {
	t.Helper()
	gathered, err := h.reg.Gather()
	require.NoError(t, err)
	return sumReloads(gathered, result, SourceFile)
}

// A rotation is still seen with the database down; the retry applies it once the database is back.
func TestReconcileFilesReadsNoDatabaseForAnUnchangedInput(t *testing.T) {
	db := &flakyDB{Database: database.NewMemory()}
	h := newRotationHarness(t, db)
	outcome, err := h.attempt(TriggerChange)
	require.NoError(t, err)
	require.Equal(t, OutcomeApplied, outcome, "the first attempt records the input")
	reads := db.reads.Load()

	db.down.Store(true)
	outcome, err = h.attempt(TriggerChange)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSkipped, outcome, "nothing changed, nothing attempted")
	assert.Equal(t, reads, db.reads.Load(), "the database is not read")
	assert.Equal(t, 0.0, h.reloads(t, resultFailure))

	require.NoError(t, os.WriteFile(h.secret, []byte("rotated"), 0o600))
	outcome, err = h.attempt(TriggerChange)
	require.ErrorIs(t, err, ErrDatabaseUnavailable)
	assert.Equal(t, OutcomeRetry, outcome, "the rotation is seen and waits for the database")
	assert.Equal(t, 1.0, h.reloads(t, resultFailure))
	assert.Equal(t, "first", h.r.apiState["slack"]["token"], "the running output keeps its previous secret")

	db.down.Store(false)
	outcome, err = h.attempt(TriggerRetry)
	require.NoError(t, err)
	assert.Equal(t, OutcomeApplied, outcome)
	assert.Equal(t, "rotated", h.r.apiState["slack"]["token"])
	assert.Equal(t, 1.0, h.reloads(t, resultSuccess))
}

func TestReconcileFilesSeesARotationWithTheFilesUnchanged(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(secret, []byte("first"), 0o600))
	var builds atomic.Int32
	typ := stubOutputType("slack", nil)
	typ.Schema.Fields = []output.SchemaField{{Name: "token", Type: "string", Secret: true}}
	typ.New = func(_ map[string]any, _ output.Deps) (output.Driver, error) {
		builds.Add(1)
		return &testutil.MockDriver{DriverName: "slack"}, nil
	}
	cat, err := catalog.New([]output.Type{typ})
	require.NoError(t, err)
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs: {}\n")
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	r := NewReloader(&ReloaderConfig{
		OutputPaths: []string{path}, Catalog: cat, Dispatcher: env.d, Database: database.NewMemory(),
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)
	ctx := t.Context()
	_, err = r.ApplyOutput(ctx, "slack", 0, map[string]any{"token_file": secret})
	require.NoError(t, err)

	outcome, err := r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerChange)
	require.NoError(t, err)
	assert.Equal(t, OutcomeApplied, outcome, "noop")
	require.NoError(t, os.WriteFile(secret, []byte("rotated"), 0o600))
	outcome, err = r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerChange)
	require.NoError(t, err)
	assert.Equal(t, OutcomeApplied, outcome)
	assert.Equal(t, int32(2), builds.Load(), "the rotated output is rebuilt")
}

// A change notification for pending files waits for the retry; a shutdown neither rejects nor retries.
func TestReconcileFilesOutcomesOfTransientFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack: {}\n")
	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	db := &flakyDB{Database: database.NewMemory()}
	db.down.Store(true)
	r := NewReloader(&ReloaderConfig{
		OutputPaths: []string{path}, Catalog: cat, Dispatcher: env.d, Database: db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	ctx := t.Context()

	outcome, err := r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerChange)
	require.ErrorIs(t, err, ErrDatabaseUnavailable)
	assert.Equal(t, OutcomeRetry, outcome)
	outcome, err = r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerChange)
	require.NoError(t, err)
	assert.Equal(t, OutcomeSkipped, outcome, "the retry owns the pending change")
	outcome, _ = r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerRetry)
	assert.Equal(t, OutcomeRetry, outcome)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	outcome, _ = r.ReconcileFiles(canceled, env.workerRunCtx, time.Second, TriggerRetry)
	assert.Equal(t, OutcomeStopped, outcome)

	db.down.Store(false)
	outcome, err = r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerRetry)
	require.NoError(t, err)
	assert.Equal(t, OutcomeApplied, outcome)

	r.Close()
	outcome, err = r.ReconcileFiles(ctx, env.workerRunCtx, time.Second, TriggerForce)
	require.ErrorIs(t, err, ErrReloaderClosed)
	assert.Equal(t, OutcomeStopped, outcome)
}
