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
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
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
	assert.NotErrorIs(t, err, pipeline.ErrInvalidOutputConfig, "init failures are not config rejections")
	assert.Contains(t, err.Error(), "init:")
	assert.Equal(t, int32(1), closeCalls.Load(), "driver must be closed on Init failure")
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

func TestBuildOutput_MisconfiguredDestinationIsRejected(t *testing.T) {
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
	require.Error(t, err)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, pipeline.ErrInvalidOutputConfig)
	assert.ErrorIs(t, err, output.ErrMisconfigured)
	assert.Contains(t, err.Error(), "health check:")
	assert.Contains(t, err.Error(), "HTTP 404")
	assert.Equal(t, int32(1), closeCalls.Load(), "driver must be closed when the destination rejects the config")
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

// A destination that never answers must not hold startup or a reload: the
// probe is bounded by healthCheckTimeout (5s).
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
