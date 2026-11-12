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

package pipeline_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

const builderTestName = "slack"

func newMockDriverType(d *testutil.MockDriver) output.Type {
	return output.Type{
		Name:   builderTestName,
		Schema: output.Schema{Fields: []output.SchemaField{}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return d, nil
		},
	}
}

func newFailingCreateType(err error) output.Type {
	return output.Type{
		Name:   builderTestName,
		Schema: output.Schema{Fields: []output.SchemaField{}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return nil, err
		},
	}
}

func TestBuildOutput_Success(t *testing.T) {
	var initCalls atomic.Int32
	var closeCalls atomic.Int32
	driver := &testutil.MockDriver{
		DriverName: "slack",
		InitFunc: func(_ context.Context) error {
			initCalls.Add(1)
			return nil
		},
		CloseFunc: func() error {
			closeCalls.Add(1)
			return nil
		},
	}
	cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
	require.NoError(t, err)

	out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, "slack", out.Name())
	assert.Equal(t, int32(1), initCalls.Load(), "Init must be called exactly once")
	assert.Equal(t, int32(0), closeCalls.Load(), "Close must NOT be called on success")
}

func TestBuildOutput_CatalogCreateError(t *testing.T) {
	createErr := errors.New("create went boom")
	cat, err := catalog.New([]output.Type{newFailingCreateType(createErr)})
	require.NoError(t, err)

	out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, createErr, "create error must propagate via %%w")
	assert.ErrorIs(t, err, pipeline.ErrInvalidOutputConfig)
	assert.Contains(t, err.Error(), "create:", "error must carry the create: prefix")
}

func TestBuildOutput_InitError(t *testing.T) {
	initErr := errors.New("init blew up")
	var closeCalls atomic.Int32
	driver := &testutil.MockDriver{
		DriverName: "slack",
		InitFunc:   func(_ context.Context) error { return initErr },
		CloseFunc: func() error {
			closeCalls.Add(1)
			return nil
		},
	}
	cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
	require.NoError(t, err)

	out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, initErr)
	assert.ErrorIs(t, err, pipeline.ErrInvalidOutputConfig, "Init reads only local state, so its failure refuses the config")
	assert.Equal(t, pipeline.PhaseBuild, pipeline.ConfigPhase(err))
	assert.Contains(t, err.Error(), "init:")
	assert.Equal(t, int32(1), closeCalls.Load(), "driver must be closed on Init failure")
}

// The panic value never reaches the error, and a panic in BuildEach's goroutines does not crash the process.
func TestBuildOutput_PanicIsABuildError(t *testing.T) {
	const secretCanary = "PANIC-CANARY-1f3a"
	const value = "makechan: size out of range " + secretCanary
	for _, tc := range []struct {
		name string
		typ  output.Type
	}{
		{name: "new", typ: output.Type{
			Name: builderTestName, Schema: output.Schema{Fields: []output.SchemaField{}},
			New: func(map[string]any, output.Deps) (output.Driver, error) { panic(value) },
		}},
		{name: "init", typ: newMockDriverType(&testutil.MockDriver{
			DriverName: builderTestName, InitFunc: func(context.Context) error { panic(value) },
		})},
		{name: "probe", typ: newMockDriverType(&testutil.MockDriver{
			DriverName: builderTestName, HealthCheckFunc: func(context.Context) error { panic(value) },
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cat, err := catalog.New([]output.Type{tc.typ})
			require.NoError(t, err)
			outs, failures := pipeline.BuildEach(context.Background(), cat,
				map[string]map[string]any{builderTestName: {}}, testutil.DefaultRuntimeConfig(), output.Deps{})
			assert.Empty(t, outs)
			require.ErrorIs(t, failures[builderTestName], pipeline.ErrBuildPanicked)
			assert.NotErrorIs(t, failures[builderTestName], pipeline.ErrInvalidOutputConfig)
			assert.NotContains(t, failures[builderTestName].Error(), secretCanary)
		})
	}
}

// An explicit 0 or a negative value is refused once, by the schema, with the range in the message.
func TestBuildOutput_RefusesRuntimeValuesOutOfRange(t *testing.T) {
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	for _, tc := range []struct {
		runtime map[string]any
		name    string
		want    string
	}{
		{name: "queue size negative", runtime: map[string]any{"queue_size": -1}, want: "runtime.queue_size: must be an integer between 1 and 100000"},
		{name: "queue size zero", runtime: map[string]any{"queue_size": 0}, want: "runtime.queue_size: must be an integer between 1 and 100000"},
		{name: "workers negative", runtime: map[string]any{"workers": -2}, want: "runtime.workers: must be an integer between 1 and 256"},
		{name: "workers above max", runtime: map[string]any{"workers": 257}, want: "runtime.workers: must be an integer between 1 and 256"},
		{name: "attempts negative", runtime: map[string]any{"retry": map[string]any{"max_attempts": -1}},
			want: "runtime.retry.max_attempts: must be an integer between 1 and 100"},
		{name: "interval negative", runtime: map[string]any{"retry": map[string]any{"initial_interval": "-1s"}},
			want: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "interval zero text", runtime: map[string]any{"retry": map[string]any{"initial_interval": "0s"}},
			want: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "interval integer zero", runtime: map[string]any{"retry": map[string]any{"initial_interval": 0}},
			want: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "interval json zero", runtime: map[string]any{"retry": map[string]any{"initial_interval": json.Number("0")}},
			want: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "max interval integer zero", runtime: map[string]any{"retry": map[string]any{"max_interval": 0}},
			want: "runtime.retry.max_interval: must be a duration between 1ms and 1h"},
		{name: "multiplier zero", runtime: map[string]any{"retry": map[string]any{"multiplier": 0}},
			want: "runtime.retry.multiplier: must be a number between 1 and 10"},
		{name: "threshold zero", runtime: map[string]any{"circuit_breaker": map[string]any{"failure_threshold": 0}},
			want: "runtime.circuit_breaker.failure_threshold: must be an integer between 1 and 10000"},
		{name: "reset timeout negative", runtime: map[string]any{"circuit_breaker": map[string]any{"reset_timeout": "-1s"}},
			want: "runtime.circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
		{name: "reset timeout integer zero", runtime: map[string]any{"circuit_breaker": map[string]any{"reset_timeout": 0}},
			want: "runtime.circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
		{name: "reset timeout json zero", runtime: map[string]any{"circuit_breaker": map[string]any{"reset_timeout": json.Number("0")}},
			want: "runtime.circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := map[string]any{"host": "http://127.0.0.1:1", "runtime": tc.runtime}
			_, err := pipeline.BuildOutput(context.Background(), cat, "webhook", raw, testutil.DefaultRuntimeConfig(), output.Deps{})
			require.ErrorIs(t, err, pipeline.ErrInvalidOutputConfig)
			assert.Equal(t, pipeline.PhaseValidate, pipeline.ConfigPhase(err))
			fields, ok := errors.AsType[utils.ValidationErrors](err)
			require.True(t, ok)
			assert.Equal(t, tc.want, fields.Error())
		})
	}
}

func TestConfigPhase(t *testing.T) {
	assert.Equal(t, pipeline.PhaseValidate, pipeline.ConfigPhase(errors.New("other")))
	assert.Equal(t, pipeline.PhaseValidate, pipeline.ConfigPhase(fmt.Errorf("secrets: %w", pipeline.ErrInvalidOutputConfig)))
	cat, err := catalog.New([]output.Type{newFailingCreateType(errors.New("bad field"))})
	require.NoError(t, err)
	_, err = pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	assert.Equal(t, pipeline.PhaseValidate, pipeline.ConfigPhase(fmt.Errorf("apply: %w", err)))
}

func TestBuildOutput_RuntimeMergeRunsBeforeInit(t *testing.T) {
	var initCalls atomic.Int32
	driver := &testutil.MockDriver{
		DriverName: "slack",
		InitFunc:   func(context.Context) error { initCalls.Add(1); return nil },
		RuntimeConfigFunc: func() output.RuntimeConfig {
			return output.RuntimeConfig{Workers: 1000}
		},
	}
	cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
	require.NoError(t, err)

	_, err = pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.ErrorIs(t, err, pipeline.ErrInvalidOutputConfig)
	assert.Zero(t, initCalls.Load())
	fields, ok := errors.AsType[utils.ValidationErrors](err)
	require.True(t, ok, "the field errors stay in the chain")
	assert.Equal(t, "runtime.workers", fields[0].Field)
}

type batchMock struct{ testutil.MockDriver }

func (*batchMock) SendBatch(context.Context, []*event.Event) error { return nil }

func TestBuildOutput_InheritedBatchingOnlyBoundsBatchSenders(t *testing.T) {
	defaults := testutil.DefaultRuntimeConfig()
	defaults.Workers = 256
	defaults.Batching = &output.BatchingConfig{Enabled: new(true), BatchSize: 10_000, FlushInterval: time.Second}
	for _, tc := range []struct {
		driver  output.Driver
		name    string
		refused bool
	}{
		{name: "single sender", driver: &testutil.MockDriver{DriverName: "slack"}},
		{name: "batch sender", driver: &batchMock{testutil.MockDriver{DriverName: "slack"}}, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cat, err := catalog.New([]output.Type{{
				Name: builderTestName, Schema: output.Schema{Fields: []output.SchemaField{}},
				New: func(map[string]any, output.Deps) (output.Driver, error) { return tc.driver, nil },
			}})
			require.NoError(t, err)
			out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, defaults, output.Deps{})
			if tc.refused {
				require.ErrorIs(t, err, pipeline.ErrInvalidOutputConfig)
				assert.Contains(t, err.Error(), "workers × batch_size is limited to 100000")
				return
			}
			require.NoError(t, err)
			_ = out.Close()
			assert.True(t, defaults.Batching.IsEnabled(), "the shared defaults are not changed")
		})
	}
}

func TestBuildOutput_RuntimeMergeError(t *testing.T) {
	var closeCalls atomic.Int32
	driver := &testutil.MockDriver{
		DriverName: "slack",
		RuntimeConfigFunc: func() output.RuntimeConfig {
			return output.RuntimeConfig{MinPriority: event.Priority("not-a-priority")}
		},
		CloseFunc: func() error {
			closeCalls.Add(1)
			return nil
		},
	}
	cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
	require.NoError(t, err)

	out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, pipeline.ErrInvalidOutputConfig)
	assert.Contains(t, err.Error(), "runtime merge:")
	assert.Equal(t, int32(1), closeCalls.Load(), "driver must be closed on merge failure")
}

// The first delivery clears the warning.
func TestBuildOutput_MisconfiguredDestinationStartsDegraded(t *testing.T) {
	var closeCalls atomic.Int32
	driver := &testutil.MockDriver{
		DriverName: "slack",
		HealthCheckFunc: func(context.Context) error {
			return fmt.Errorf("%w: slack response: HTTP 404 Not Found", output.ErrMisconfigured)
		},
		CloseFunc: func() error {
			closeCalls.Add(1)
			return nil
		},
	}
	cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
	require.NoError(t, err)

	out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.NoError(t, err)
	status := out.GetStatus()
	assert.Equal(t, pipeline.HealthDegraded, status.Status)
	assert.Equal(t, "health check failed before start: destination rejects the configuration: slack response: HTTP 404 Not Found", status.LastWarning)
	assert.Equal(t, pipeline.WarningDestination, status.WarningKind)
	assert.Zero(t, closeCalls.Load(), "the output runs")
}

func TestBuildOutput_UnreachableDestinationStartsDegraded(t *testing.T) {
	driver := &testutil.MockDriver{
		DriverName: "slack",
		HealthCheckFunc: func(context.Context) error {
			return errors.New("connection refused")
		},
	}
	cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
	require.NoError(t, err)

	out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.NoError(t, err)
	status := out.GetStatus()
	assert.Equal(t, pipeline.HealthDegraded, status.Status)
	assert.Equal(t, "health check failed before start: connection refused", status.LastWarning)
}

func TestBuildOutput_HealthCheckIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		driver := &testutil.MockDriver{
			DriverName: "slack",
			HealthCheckFunc: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
		}
		cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
		require.NoError(t, err)

		start := time.Now()
		out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
		require.NoError(t, err)
		assert.Equal(t, 5*time.Second, time.Since(start))
		assert.Equal(t, pipeline.HealthDegraded, out.GetStatus().Status)
		assert.Contains(t, out.GetStatus().LastWarning, "deadline exceeded")
	})
}

func probeType(name string, probe func(context.Context) error, closed *atomic.Int32) output.Type {
	return output.Type{
		Name:   name,
		Schema: output.Schema{Fields: []output.SchemaField{}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName:      name,
				HealthCheckFunc: probe,
				CloseFunc: func() error {
					closed.Add(1)
					return nil
				},
			}, nil
		},
	}
}

func TestBuildOutputs_ProbesRunConcurrently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var closed atomic.Int32
		slow := func(context.Context) error {
			time.Sleep(3 * time.Second)
			return nil
		}
		cat, err := catalog.New([]output.Type{probeType("a", slow, &closed), probeType("b", slow, &closed), probeType("c", slow, &closed)})
		require.NoError(t, err)

		start := time.Now()
		outs, err := pipeline.BuildOutputs(context.Background(), cat,
			map[string]map[string]any{"a": {}, "b": {}, "c": {}}, testutil.DefaultRuntimeConfig(), output.Deps{})
		require.NoError(t, err)
		assert.Equal(t, 3*time.Second, time.Since(start))
		assert.Len(t, outs, 3)
		assert.Zero(t, closed.Load())
	})
}

func TestBuildOutputs_FailureClosesTheOthers(t *testing.T) {
	var closed atomic.Int32
	ok := func(context.Context) error { return nil }
	bad := probeType("b", ok, &closed)
	bad.New = func(map[string]any, output.Deps) (output.Driver, error) {
		return &testutil.MockDriver{DriverName: "b", InitFunc: func(context.Context) error { return errors.New("bad key file") },
			CloseFunc: func() error { closed.Add(1); return nil }}, nil
	}
	cat, err := catalog.New([]output.Type{probeType("a", ok, &closed), bad, probeType("c", ok, &closed)})
	require.NoError(t, err)

	outs, err := pipeline.BuildOutputs(context.Background(), cat,
		map[string]map[string]any{"a": {}, "b": {}, "c": {}}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.Error(t, err)
	assert.Nil(t, outs)
	assert.Contains(t, err.Error(), `output "b"`)
	assert.Equal(t, int32(3), closed.Load(), "the failed driver and both built outputs are closed")
}

func TestBuildOutputs_ProbeFailureKeepsSiblings(t *testing.T) {
	var closed atomic.Int32
	ok := func(context.Context) error { return nil }
	bad := func(context.Context) error { return fmt.Errorf("%w: HTTP 401", output.ErrMisconfigured) }
	cat, err := catalog.New([]output.Type{probeType("a", ok, &closed), probeType("b", bad, &closed)})
	require.NoError(t, err)

	outs, err := pipeline.BuildOutputs(context.Background(), cat,
		map[string]map[string]any{"a": {}, "b": {}}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.NoError(t, err)
	require.Len(t, outs, 2)
	assert.Equal(t, pipeline.HealthIdle, outs["a"].GetStatus().Status)
	assert.Equal(t, pipeline.HealthDegraded, outs["b"].GetStatus().Status)
	for _, out := range outs {
		_ = out.Close()
	}
}

func TestBuildOutput_MisconfiguredInitIsInvalidConfig(t *testing.T) {
	driver := &testutil.MockDriver{
		DriverName: "slack",
		InitFunc: func(context.Context) error {
			return fmt.Errorf("%w: HTTP 403", output.ErrMisconfigured)
		},
	}
	cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
	require.NoError(t, err)

	_, err = pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.ErrorIs(t, err, pipeline.ErrInvalidOutputConfig)
	assert.Contains(t, err.Error(), "init:")
}

func TestBuildOutput_HealthCheckDisabled(t *testing.T) {
	var probes atomic.Int32
	driver := &testutil.MockDriver{
		DriverName: "slack",
		HealthCheckFunc: func(context.Context) error {
			probes.Add(1)
			return fmt.Errorf("%w: HTTP 401", output.ErrMisconfigured)
		},
		RuntimeConfigFunc: func() output.RuntimeConfig {
			disabled := false
			return output.RuntimeConfig{HealthCheck: &disabled}
		},
	}
	cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
	require.NoError(t, err)

	out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, testutil.DefaultRuntimeConfig(), output.Deps{})
	require.NoError(t, err)
	assert.Zero(t, probes.Load())
	assert.Equal(t, pipeline.HealthIdle, out.GetStatus().Status)
}

func TestBuildOutput_AppliesRuntimeDefaults(t *testing.T) {
	driver := &testutil.MockDriver{DriverName: "slack"}
	cat, err := catalog.New([]output.Type{newMockDriverType(driver)})
	require.NoError(t, err)

	defaults := testutil.DefaultRuntimeConfig()
	defaults.QueueSize = 42

	out, err := pipeline.BuildOutput(context.Background(), cat, "slack", map[string]any{}, defaults, output.Deps{})
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, 42, out.GetStatus().QueueCapacity, "defaults must flow through the merge step")
}
