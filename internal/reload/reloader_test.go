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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	databasetestutil "github.com/falcosecurity/falcosidekick/internal/database/testutil"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

func stubOutputType(name string, sendFunc func(context.Context, *event.Event) error) output.Type {
	return output.Type{
		Name: name,
		Schema: output.Schema{
			Fields: []output.SchemaField{},
		},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: name,
				SendFunc:   sendFunc,
			}, nil
		},
	}
}

func failingInitOutputType(name string) output.Type {
	return output.Type{
		Name: name,
		Schema: output.Schema{
			Fields: []output.SchemaField{},
		},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: name,
				InitFunc: func(_ context.Context) error {
					return fmt.Errorf("init failed for %s", name)
				},
			}, nil
		},
	}
}

func writeOutputsYAML(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

type reloaderTestEnv struct {
	d            *pipeline.Dispatcher
	workerRunCtx context.Context
	stopWorkers  context.CancelFunc
}

func newReloaderTestEnv(t *testing.T, outputs []*pipeline.Output) *reloaderTestEnv {
	t.Helper()
	d := pipeline.NewDispatcher(outputs)
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)
	return &reloaderTestEnv{d: d, workerRunCtx: workerRunCtx, stopWorkers: stopWorkers}
}

func (e *reloaderTestEnv) shutdown(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = e.d.Shutdown(ctx, e.stopWorkers)
}

func TestReloaderSuccessAddOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: https://hooks.slack.com/new\n")

	var slackCalls atomic.Int64
	cat, err := catalog.New([]output.Type{
		stubOutputType("slack", func(_ context.Context, _ *event.Event) error {
			slackCalls.Add(1)
			return nil
		}),
	})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	env.d.DispatchEvent(&event.Event{
		Priority: event.PriorityError,
		Rule:     "test",
		Source:   "test",
	})

	env.shutdown(t)

	assert.Equal(t, int64(1), slackCalls.Load())
}

func TestReloaderSuccessRemoveOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs: {}\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	initialOut := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &output.RuntimeConfig{
		QueueSize: 100, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: time.Second},
	}, nil)

	env := newReloaderTestEnv(t, []*pipeline.Output{initialOut})
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"slack": {"secret_endpoint": "old"}},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	names := env.d.OutputNames()
	assert.Empty(t, names, "slack must be removed")
}

func TestReloaderNoChangeIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: same\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	initial := map[string]map[string]any{"slack": {"secret_endpoint": "same"}}
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  initial,
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))
}

func TestReloaderParseErrorKeepsOldConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "invalid: [yaml: {{{")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"slack": {"secret_endpoint": "old"}},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reload parse")
}

func TestReloaderUnknownOutputKeepsOldConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  unknown_output:\n    host: http://x\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output type")
}

func TestReloaderConcurrentReloadsSerialized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  loki:\n    host: http://loki:3100\n")

	cat, err := catalog.New([]output.Type{stubOutputType("loki", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	var wg sync.WaitGroup
	var errCount atomic.Int64
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second); err != nil {
				errCount.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(0), errCount.Load())
}

func TestReloaderChangedOutputTriggersReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")

	var calls atomic.Int64
	cat, err := catalog.New([]output.Type{
		stubOutputType("slack", func(_ context.Context, _ *event.Event) error {
			calls.Add(1)
			return nil
		}),
	})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	initial := map[string]map[string]any{"slack": {"secret_endpoint": "old"}}
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: old\n")

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  initial,
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: new\n")
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	env.d.DispatchEvent(&event.Event{
		Priority: event.PriorityError,
		Rule:     "test",
		Source:   "test",
	})

	env.shutdown(t)

	assert.GreaterOrEqual(t, calls.Load(), int64(1), "replaced output must receive events")
}

func TestReloaderInitFailureClosesPartialOutputs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: x\n  broken:\n    host: y\n")

	var closeCalled atomic.Bool
	slackType := output.Type{
		Name:   "slack",
		Schema: output.Schema{Fields: []output.SchemaField{}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: "slack",
				CloseFunc: func() error {
					closeCalled.Store(true)
					return nil
				},
			}, nil
		},
	}

	cat, err := catalog.New([]output.Type{
		slackType,
		failingInitOutputType("broken"),
	})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)
	assert.Error(t, err, "reload must fail when any output Init fails")
	assert.Contains(t, err.Error(), "init")

	assert.Empty(t, env.d.OutputNames(), "no outputs must be added on partial failure")
}

func TestReloaderMisconfiguredDestinationKeepsOldOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")

	var delivered, closedRejected atomic.Int64
	slackType := output.Type{
		Name:   "slack",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "secret_endpoint", Type: "string"}}},
		New: func(cfg map[string]any, _ output.Deps) (output.Driver, error) {
			wrong := cfg["secret_endpoint"] == "wrong"
			return &testutil.MockDriver{
				DriverName: "slack",
				SendFunc: func(context.Context, *event.Event) error {
					delivered.Add(1)
					return nil
				},
				HealthCheckFunc: func(context.Context) error {
					if wrong {
						return fmt.Errorf("%w: slack response: HTTP 404 Not Found", output.ErrMisconfigured)
					}
					return nil
				},
				CloseFunc: func() error {
					if wrong {
						closedRejected.Add(1)
					}
					return nil
				},
			}, nil
		},
	}
	cat, err := catalog.New([]output.Type{slackType})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: good\n")
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})
	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: wrong\n")
	err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "health check")
	assert.Equal(t, int64(1), closedRejected.Load(), "the rejected driver is closed")

	env.d.DispatchEvent(&event.Event{Priority: event.PriorityError, Rule: "test", Source: "test"})
	assert.Eventually(t, func() bool { return delivered.Load() == 1 }, 5*time.Second, 10*time.Millisecond,
		"the previous output still delivers")
}

const (
	metricReloadTotal       = "falcosidekick_reload_total"
	metricReloadFailures    = "falcosidekick_reload_failures_total"
	metricReloadPartial     = "falcosidekick_reload_partial_total"
	metricReloadLastSuccess = "falcosidekick_reload_last_success_timestamp"
)

func getMetricValue(gathered []*dto.MetricFamily, name string) float64 {
	for _, mf := range gathered {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	return 0
}

func getLastSuccessTimestamp(gathered []*dto.MetricFamily) float64 {
	for _, mf := range gathered {
		if mf.GetName() == metricReloadLastSuccess {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	return 0
}

func TestReloaderReplaceRetireTimeoutKeepsLiveReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")

	var newSendCalls atomic.Int64
	fastType := output.Type{
		Name:   "myout",
		Schema: output.Schema{Fields: []output.SchemaField{}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: "myout",
				SendFunc: func(_ context.Context, _ *event.Event) error {
					newSendCalls.Add(1)
					return nil
				},
			}, nil
		},
	}
	cat, err := catalog.New([]output.Type{fastType})
	require.NoError(t, err)

	// Send blocks forever and ignores ctx.
	slowDriver := &testutil.MockDriver{
		DriverName: "myout",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			select {} // block forever
		},
	}
	initialOut := pipeline.NewOutput(slowDriver, &output.RuntimeConfig{
		QueueSize: 100, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: time.Second},
	}, nil)

	env := newReloaderTestEnv(t, []*pipeline.Output{initialOut})
	defer env.shutdown(t)

	env.d.DispatchEvent(&event.Event{Priority: event.PriorityError, Rule: "test", Source: "test"})
	time.Sleep(30 * time.Millisecond)

	writeOutputsYAML(t, path, "outputs:\n  myout:\n    host: http://changed\n")

	reg := prometheus.NewRegistry()
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"myout": {"host": "http://old"}},
	})

	// The short retireTimeout makes the old output's retire time out.
	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reloadCancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 100*time.Millisecond)

	require.NoError(t, err, "Reload must succeed: replacement is live, retire timeout is a warning")

	env.d.DispatchEvent(&event.Event{Priority: event.PriorityError, Rule: "test2", Source: "test"})
	time.Sleep(50 * time.Millisecond)
	assert.GreaterOrEqual(t, newSendCalls.Load(), int64(1), "live replacement must receive events")

	assert.Equal(t, "http://changed", r.fileState["myout"]["host"], "file state must reflect new config")

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadTotal), "reload_total must be 1")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadFailures), "reload_failures_total must be 0")
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadPartial), "reload_partial_total must be 1")
	assert.Equal(t, float64(0), getLastSuccessTimestamp(gathered), "reload_last_success_timestamp must NOT be updated on partial")
}

func TestReloaderRemoveRetireTimeoutIsWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")

	slowDriver := &testutil.MockDriver{
		DriverName: "myout",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			select {} // block forever
		},
	}
	initialOut := pipeline.NewOutput(slowDriver, &output.RuntimeConfig{
		QueueSize: 100, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: time.Second},
	}, nil)

	cat, err := catalog.New([]output.Type{stubOutputType("myout", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, []*pipeline.Output{initialOut})
	defer env.shutdown(t)

	env.d.DispatchEvent(&event.Event{Priority: event.PriorityError, Rule: "test", Source: "test"})
	time.Sleep(30 * time.Millisecond)

	writeOutputsYAML(t, path, "outputs: {}\n")

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"myout": {"host": "http://old"}},
	})

	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reloadCancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 100*time.Millisecond)

	require.NoError(t, err, "Reload must succeed: retire timeout is a warning")
	assert.Empty(t, env.d.OutputNames(), "output must be removed from dispatcher")
}

func TestReloaderRejectsDuringShutdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: x\n")

	var closeCalled atomic.Bool
	slackType := output.Type{
		Name:   "slack",
		Schema: output.Schema{Fields: []output.SchemaField{}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: "slack",
				CloseFunc: func() error {
					closeCalled.Store(true)
					return nil
				},
			}, nil
		},
	}

	cat, err := catalog.New([]output.Type{slackType})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()
	_ = env.d.Shutdown(shutdownCtx, env.stopWorkers)

	reg := prometheus.NewRegistry()
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), time.Second)
	defer reloadCancel()
	err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "dispatcher stopped")

	assert.True(t, closeCalled.Load(), "orphaned output must be closed on rejection")
	assert.Empty(t, r.fileState, "file state must not be updated on rejected reload")

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadFailures), "reload_failures_total must be 1")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadPartial), "reload_partial_total must be 0")
	assert.Equal(t, float64(0), getLastSuccessTimestamp(gathered), "reload_last_success_timestamp must not be updated on failure")
}

func TestReloadRetireTimeoutConfigValidation(t *testing.T) {
	cfg := core.ReloadConfig{PollInterval: 0, RetireTimeout: -1 * time.Second}
	errs := cfg.Validate()
	assert.NotEmpty(t, errs, "negative retire_timeout must fail validation")
}

func TestReloadNoOpCountsAsAttempt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    host: same\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	reg := prometheus.NewRegistry()
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"slack": {"host": "same"}},
	})

	reloadCtx := context.Background()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadTotal), "no-op reload must still count as an attempt")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadFailures), "no-op must not be a failure")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadPartial), "no-op must not be partial")
	assert.Equal(t, float64(0), getLastSuccessTimestamp(gathered), "no-op must not update last success timestamp")
}

func TestReloaderSuccessWithDBSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: https://hooks.slack.com/new\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	reg := prometheus.NewRegistry()
	db := &databasetestutil.Mock{}
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	assert.Contains(t, r.fileState, "slack", "file state must include new output")

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadTotal), "reload_total must be 1")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadFailures), "reload_failures_total must be 0")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadPartial), "reload_partial_total must be 0")
	assert.NotEqual(t, float64(0), getLastSuccessTimestamp(gathered), "reload_last_success_timestamp must be updated")
}

func TestReloaderPartialSuccessDBSyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: https://hooks.slack.com/new\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	reg := prometheus.NewRegistry()
	db := &databasetestutil.Mock{ProvisionErr: fmt.Errorf("db provision failed")}
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Registry:        reg,
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The runtime accepted the config, so a DB failure does not fail Reload.
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second))

	assert.Contains(t, r.fileState, "slack", "file state must reflect new config despite DB failure")

	gathered, gatherErr := reg.Gather()
	require.NoError(t, gatherErr)
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadTotal), "reload_total must be 1")
	assert.Equal(t, float64(0), getMetricValue(gathered, metricReloadFailures), "reload_failures_total must be 0")
	assert.Equal(t, float64(1), getMetricValue(gathered, metricReloadPartial), "reload_partial_total must be 1")
	assert.Equal(t, float64(0), getLastSuccessTimestamp(gathered), "reload_last_success_timestamp must NOT be updated on partial")
}

func newApplyReloader(t *testing.T, cat *catalog.Catalog, env *reloaderTestEnv, initial map[string]map[string]any) *Reloader {
	t.Helper()
	r := NewReloader(&ReloaderConfig{
		OutputPaths:     nil,
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  initial,
	})
	r.BindWorkerContext(env.workerRunCtx, 2*time.Second)
	return r
}

func TestReloaderApplyOutput_RequiresBind(t *testing.T) {
	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := NewReloader(&ReloaderConfig{
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	err = r.ApplyOutput(context.Background(), "slack", 0, map[string]any{"secret_endpoint": "x"})
	require.ErrorIs(t, err, ErrReloaderNotBound)

	err = r.RemoveOutput(context.Background(), "slack", 0)
	require.ErrorIs(t, err, ErrReloaderNotBound)
}

func TestReloaderBindWorkerContext_PanicsOnSecondCall(t *testing.T) {
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	r := NewReloader(&ReloaderConfig{
		Catalog: cat, Dispatcher: env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)

	assert.Panics(t, func() {
		r.BindWorkerContext(env.workerRunCtx, time.Second)
	})
}

func TestReloaderApplyOutput_AddsNewOutput(t *testing.T) {
	var slackCalls atomic.Int64
	cat, err := catalog.New([]output.Type{
		stubOutputType("slack", func(_ context.Context, _ *event.Event) error {
			slackCalls.Add(1)
			return nil
		}),
	})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := newApplyReloader(t, cat, env, map[string]map[string]any{})

	require.NoError(t, r.ApplyOutput(context.Background(), "slack", 0, map[string]any{"secret_endpoint": "https://hooks.slack.com/ui"}))

	assert.Contains(t, env.d.OutputNames(), "slack", "ApplyOutput must add the output to the dispatcher")

	env.d.DispatchEvent(&event.Event{Priority: event.PriorityError, Rule: "t", Source: "t"})
	env.shutdown(t)
	assert.Equal(t, int64(1), slackCalls.Load())
}

func TestReloaderApplyOutput_ReplacesExistingOutput(t *testing.T) {
	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	initialOut := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &output.RuntimeConfig{
		QueueSize: 100, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: time.Second},
	}, nil)
	env := newReloaderTestEnv(t, []*pipeline.Output{initialOut})
	defer env.shutdown(t)

	r := newApplyReloader(t, cat, env, map[string]map[string]any{"slack": {"secret_endpoint": "old"}})

	require.NoError(t, r.ApplyOutput(context.Background(), "slack", 0, map[string]any{"secret_endpoint": "new"}))

	assert.Contains(t, env.d.OutputNames(), "slack")
}

// Two writers that read the same version: the second must not overwrite the first.
func TestReloaderApplyOutput_StaleVersionConflicts(t *testing.T) {
	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	db := database.NewMemory()
	r := NewReloader(&ReloaderConfig{
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)
	ctx := context.Background()

	require.NoError(t, r.ApplyOutput(ctx, "slack", 0, map[string]any{"secret_endpoint": "first"}))
	require.ErrorIs(t, r.ApplyOutput(ctx, "slack", 0, map[string]any{"secret_endpoint": "create again"}), core.ErrVersionConflict)

	require.NoError(t, r.ApplyOutput(ctx, "slack", 1, map[string]any{"secret_endpoint": "second"}))
	require.ErrorIs(t, r.ApplyOutput(ctx, "slack", 1, map[string]any{"secret_endpoint": "lost update"}), core.ErrVersionConflict)

	stored, err := db.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	assert.Equal(t, int64(2), stored.Version)
	assert.Equal(t, "second", stored.Config["secret_endpoint"])
}

// The database keeps the secret file reference; the output is built from the file content, and a
// rotated secret file is a change at the next reload.
func TestReloaderStoresSecretReferencesAndBuildsFromTheirContent(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(secret, []byte("first"), 0o600))
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    token_file: "+secret+"\n")

	var seen []string
	typ := stubOutputType("slack", nil)
	typ.Schema.Fields = []output.SchemaField{{Name: "token", Type: "string", Secret: true}}
	typ.New = func(cfg map[string]any, _ output.Deps) (output.Driver, error) {
		seen = append(seen, fmt.Sprint(cfg["token"]))
		return &testutil.MockDriver{DriverName: "slack"}, nil
	}
	cat, err := catalog.New([]output.Type{typ})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	db := database.NewMemory()
	r := NewReloader(&ReloaderConfig{
		OutputPaths: []string{path}, Catalog: cat, Dispatcher: env.d, Database: db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)
	ctx := context.Background()

	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
	stored, err := db.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"token_file": secret}, stored.Config)

	require.NoError(t, os.WriteFile(secret, []byte("rotated"), 0o600))
	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
	assert.Equal(t, []string{"first", "rotated"}, seen)
	after, err := db.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	assert.Equal(t, stored.Version, after.Version, "the stored reference did not change")
}

func TestReloaderApplyOutput_UnknownTypeRejected(t *testing.T) {
	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := newApplyReloader(t, cat, env, map[string]map[string]any{})

	err = r.ApplyOutput(context.Background(), "not-a-real-output", 0, map[string]any{})
	require.ErrorIs(t, err, ErrUnknownOutputType)
	assert.Empty(t, env.d.OutputNames(), "dispatcher must not gain the unknown output")
}

func TestReloaderApplyOutput_InitFailureLeavesStateUnchanged(t *testing.T) {
	cat, err := catalog.New([]output.Type{failingInitOutputType("broken")})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := newApplyReloader(t, cat, env, map[string]map[string]any{})

	err = r.ApplyOutput(context.Background(), "broken", 0, map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "apply init")
	assert.Empty(t, env.d.OutputNames(), "dispatcher must be untouched on Init failure")
}

func TestReloaderApplyOutput_RejectedConfigNeverEchoesValues(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := newApplyReloader(t, cat, env, map[string]map[string]any{})

	err = r.ApplyOutput(context.Background(), "webhook", 0, map[string]any{"host": "https://u:" + sentinel + "@ho st/x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host: invalid URL")
	assert.NotContains(t, err.Error(), sentinel)
	assert.Empty(t, env.d.OutputNames(), "dispatcher must be untouched on rejected config")
}

func TestReloaderFileReloadNeverEchoesValues(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "rejected url",
			content: "outputs:\n  webhook:\n    host: \"https://u:" + sentinel + "@ho st/x\"\n",
			want:    "host: invalid URL",
		},
		{
			name:    "removed url field",
			content: "outputs:\n  webhook:\n    url: https://h/" + sentinel + "\n",
			want:    "unknown keys: url",
		},
		{
			name:    "rejected secret type",
			content: "outputs:\n  webhook:\n    host: https://h\n    password:\n      a: " + sentinel + "\n",
			want:    "password: invalid type",
		},
		{
			name:    "wrong file structure",
			content: "outputs:\n  webhook: " + sentinel + "\n",
			want:    "invalid structure",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "outputs.yaml")
			writeOutputsYAML(t, path, tc.content)

			cat, err := catalog.New([]output.Type{webhook.OutputType})
			require.NoError(t, err)

			env := newReloaderTestEnv(t, nil)
			defer env.shutdown(t)

			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			r := NewReloader(&ReloaderConfig{
				OutputPaths:     []string{path},
				Catalog:         cat,
				Dispatcher:      env.d,
				RuntimeDefaults: testutil.DefaultRuntimeConfig(),
				Deps:            output.Deps{Logger: logger},
				Logger:          logger,
				InitialOutputs:  map[string]map[string]any{},
			})

			reloadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = r.Reload(reloadCtx, env.workerRunCtx, 10*time.Second)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), "s3cret")
			assert.NotContains(t, logs.String(), "s3cret")
			assert.Empty(t, env.d.OutputNames(), "dispatcher must be untouched on rejected config")
		})
	}
}

func TestReloaderRemoveOutput_RemovesFromDispatcher(t *testing.T) {
	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	initialOut := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &output.RuntimeConfig{
		QueueSize: 100, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: time.Second},
	}, nil)
	env := newReloaderTestEnv(t, []*pipeline.Output{initialOut})
	defer env.shutdown(t)

	r := newApplyReloader(t, cat, env, map[string]map[string]any{"slack": {"secret_endpoint": "x"}})

	require.NoError(t, r.RemoveOutput(context.Background(), "slack", 0))
	assert.NotContains(t, env.d.OutputNames(), "slack", "RemoveOutput must drop the output from the dispatcher")
}

func TestReloaderRemoveOutput_MissIsNoop(t *testing.T) {
	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := newApplyReloader(t, cat, env, map[string]map[string]any{})

	require.NoError(t, r.RemoveOutput(context.Background(), "never-existed", 0), "RemoveOutput on a missing name must be a no-op")
}

func TestReloaderApplyThenReload_FileWinsOverUIEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: file-value\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	db := &databasetestutil.Mock{Outputs: map[string]*core.OutputConfigEntry{
		"slack": {Name: "slack", Config: map[string]any{"secret_endpoint": "file-value"}, Provisioned: true},
	}}

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{"slack": {"secret_endpoint": "file-value"}},
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)

	applyCtx, applyCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer applyCancel()
	require.NoError(t, r.ApplyOutput(applyCtx, "slack", 0, map[string]any{"secret_endpoint": "ui-value"}))
	require.Contains(t, env.d.OutputNames(), "slack")
	require.Equal(t, map[string]any{"secret_endpoint": "ui-value"}, r.fileState["slack"],
		"r.fileState must track the UI edit so the next file reload sees a Changed diff")

	reloadCtx, reloadCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer reloadCancel()
	require.NoError(t, r.Reload(reloadCtx, env.workerRunCtx, time.Second))

	assert.Contains(t, env.d.OutputNames(), "slack")
	assert.Equal(t, map[string]any{"secret_endpoint": "file-value"}, r.fileState["slack"],
		"file reload must overwrite the UI edit with the file version")
}

func TestReloaderReload_DisableDeletionKeepsOrphanedOutputRunning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: slack-cfg\n  webhook:\n    host: webhook-cfg\n")

	cat, err := catalog.New([]output.Type{
		stubOutputType("slack", nil),
		stubOutputType("webhook", nil),
	})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	db := database.NewMemory()

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Provisioning:    core.ProvisioningConfig{DisableDeletion: true},
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	require.NoError(t, r.Reload(context.Background(), env.workerRunCtx, time.Second))
	require.ElementsMatch(t, []string{"slack", "webhook"}, env.d.OutputNames())

	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: slack-cfg\n")
	require.NoError(t, r.Reload(context.Background(), env.workerRunCtx, time.Second))

	assert.ElementsMatch(t, []string{"slack", "webhook"}, env.d.OutputNames(),
		"orphaned webhook must stay running when DisableDeletion=true")
	stored, err := db.GetOutputConfig(context.Background(), "webhook")
	require.NoError(t, err)
	require.NotNil(t, stored, "DB entry must be preserved when DisableDeletion=true")
	assert.True(t, stored.Provisioned)
}

func TestReloaderReload_DisableDeletionFalseRetiresOrphan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: slack-cfg\n  webhook:\n    host: webhook-cfg\n")

	cat, err := catalog.New([]output.Type{
		stubOutputType("slack", nil),
		stubOutputType("webhook", nil),
	})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	db := database.NewMemory()

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Provisioning:    core.ProvisioningConfig{DisableDeletion: false},
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})

	require.NoError(t, r.Reload(context.Background(), env.workerRunCtx, time.Second))
	require.ElementsMatch(t, []string{"slack", "webhook"}, env.d.OutputNames())

	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: slack-cfg\n")
	require.NoError(t, r.Reload(context.Background(), env.workerRunCtx, time.Second))

	assert.ElementsMatch(t, []string{"slack"}, env.d.OutputNames(),
		"orphaned webhook must be retired when DisableDeletion=false")
	stored, err := db.GetOutputConfig(context.Background(), "webhook")
	require.NoError(t, err)
	assert.Nil(t, stored, "DB entry must be deleted when DisableDeletion=false")
}

func TestReloaderReload_ReAddsNameAlreadyLiveAsReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: file-version\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	db := &databasetestutil.Mock{Outputs: map[string]*core.OutputConfigEntry{}}

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)

	require.NoError(t, r.ApplyOutput(context.Background(), "slack", 0, map[string]any{"secret_endpoint": "ui-version"}))
	require.Contains(t, env.d.OutputNames(), "slack")
	require.NotContains(t, r.fileState, "slack",
		"UI-only apply must not write to the file-view")

	require.NoError(t, r.Reload(context.Background(), env.workerRunCtx, time.Second))

	count := 0
	for _, n := range env.d.OutputNames() {
		if n == "slack" {
			count++
		}
	}
	assert.Equal(t, 1, count, "dispatcher must have exactly one slack (Replace, not duplicate Add)")
	assert.Equal(t, map[string]any{"secret_endpoint": "file-version"}, r.fileState["slack"],
		"post-reload r.fileState reflects the file version")
}

// The database decides before the dispatcher: a refused or failed write changes nothing at runtime.
func TestReloaderUIWriteRefusedByTheDatabaseLeavesTheRuntimeUntouched(t *testing.T) {
	tests := []struct {
		db      databasetestutil.Mock
		want    error
		name    string
		remove  bool
		failure float64
	}{
		{name: "apply conflict", db: databasetestutil.Mock{SaveOutputConfigErr: core.ErrVersionConflict}, want: core.ErrVersionConflict},
		{name: "apply outage", db: databasetestutil.Mock{SaveOutputConfigErr: errors.New("db down")}, want: ErrDatabaseUnavailable},
		{name: "remove conflict", db: databasetestutil.Mock{DeleteOutputConfigErr: core.ErrVersionConflict}, want: core.ErrVersionConflict, remove: true},
		{name: "remove outage", db: databasetestutil.Mock{DeleteOutputConfigErr: errors.New("db down")}, want: ErrDatabaseUnavailable, remove: true},
		{name: "version read outage", db: databasetestutil.Mock{GetOutputConfigErr: errors.New("db down")}, want: ErrDatabaseUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var built, closed atomic.Int32
			cat, err := catalog.New([]output.Type{{
				Name: "slack",
				New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
					built.Add(1)
					return &testutil.MockDriver{DriverName: "slack", CloseFunc: func() error { closed.Add(1); return nil }}, nil
				},
			}})
			require.NoError(t, err)
			running := &testutil.MockDriver{DriverName: "slack"}
			env := newReloaderTestEnv(t, []*pipeline.Output{pipeline.NewOutput(running, &output.RuntimeConfig{
				QueueSize: 100, Workers: 1,
				Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
				CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: time.Second},
			}, nil)})
			defer env.shutdown(t)
			reg := prometheus.NewRegistry()
			db := tt.db
			r := NewReloader(&ReloaderConfig{
				Catalog:         cat,
				Dispatcher:      env.d,
				Database:        &db,
				RuntimeDefaults: testutil.DefaultRuntimeConfig(),
				Deps:            output.Deps{Logger: slog.Default()},
				Registry:        reg,
				Logger:          slog.Default(),
			})
			r.BindWorkerContext(env.workerRunCtx, time.Second)

			if tt.remove {
				err = r.RemoveOutput(t.Context(), "slack", 0)
			} else {
				err = r.ApplyOutput(t.Context(), "slack", 0, map[string]any{"secret_endpoint": "x"})
			}
			require.ErrorIs(t, err, tt.want)
			if errors.Is(tt.want, ErrDatabaseUnavailable) {
				assert.NotErrorIs(t, err, core.ErrVersionConflict)
			}
			assert.Equal(t, []string{"slack"}, env.d.OutputNames(), "the running output stays")
			assert.Equal(t, built.Load(), closed.Load(), "a built replacement is closed, never swapped in")

			gathered, err := reg.Gather()
			require.NoError(t, err)
			assert.Equal(t, float64(1), getMetricValueByLabel(gathered, metricReloadFailures, "source", "ui"))
			assert.Equal(t, float64(0), getMetricValueByLabel(gathered, metricReloadPartial, "source", "ui"))
		})
	}
}

func TestReloaderRemoveOutput_FileReloadRestoresFileProvisioned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outputs.yaml")
	writeOutputsYAML(t, path, "outputs:\n  slack:\n    secret_endpoint: https://hooks.slack.com/file\n")

	cat, err := catalog.New([]output.Type{stubOutputType("slack", nil)})
	require.NoError(t, err)

	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	db := database.NewMemory()

	r := NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		Database:        db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, r.Reload(ctx, env.workerRunCtx, 10*time.Second))
	require.Contains(t, env.d.OutputNames(), "slack", "initial file reload must add slack")
	require.Contains(t, r.fileState, "slack", "file state must track file-provisioned name")

	require.NoError(t, r.RemoveOutput(ctx, "slack", 1))
	assert.NotContains(t, env.d.OutputNames(), "slack", "UI DELETE must retire the runtime output")
	assert.NotContains(t, r.fileState, "slack",
		"UI DELETE must drop the name from fileState so the next file reload re-adds it")

	require.NoError(t, r.Reload(ctx, env.workerRunCtx, 10*time.Second))
	assert.Contains(t, env.d.OutputNames(), "slack",
		"unchanged file reload after UI DELETE must restore the file-provisioned output")
	assert.Contains(t, r.fileState, "slack", "fileState must track the restored name")

	entry, err := db.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	require.NotNil(t, entry, "DB must carry the restored entry")
	assert.True(t, entry.Provisioned, "restored entry must be marked Provisioned:true")
}

func getMetricValueByLabel(gathered []*dto.MetricFamily, name, labelKey, labelValue string) float64 {
	for _, mf := range gathered {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == labelKey && l.GetValue() == labelValue {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
