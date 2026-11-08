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

package pipeline

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestRuntimeDefaultsValidateValid(t *testing.T) {
	cfg := defaultRuntimeDefaults()
	assert.Empty(t, cfg.Validate())
}

func TestRuntimeDefaultsValidateZeroValues(t *testing.T) {
	cfg := output.RuntimeConfig{}
	assert.NotEmpty(t, cfg.Validate())
}

func TestRuntimeDefaultsValidateNegativeQueueSize(t *testing.T) {
	cfg := defaultRuntimeDefaults()
	cfg.QueueSize = -1
	errs := cfg.Validate()
	assert.NotEmpty(t, errs)
}

func TestOutputGetStatus(t *testing.T) {
	out := NewOutput(&testutil.MockDriver{DriverName: "slack"}, defaultRuntimeDefaults(), nil)

	status := out.GetStatus()
	assert.Equal(t, "slack", status.Name)
	assert.Equal(t, 0, status.QueueDepth)
	assert.Equal(t, 100, status.QueueCapacity)
	assert.Equal(t, "closed", status.CircuitState)
}

func TestOutputClearsLastErrorAfterRecoveredSend(t *testing.T) {
	var attempts atomic.Int64
	out := NewOutput(&testutil.MockDriver{
		DriverName: "recovering",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			if attempts.Add(1) == 1 {
				return errors.New("temporary send failure")
			}
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	out.executeWithRetry(context.Background(), 1, func(ctx context.Context) error {
		return out.driver.Send(ctx, newTestEvent())
	})
	failed := out.GetStatus()
	require.Equal(t, "error", failed.Status)
	require.Contains(t, failed.LastError, "temporary send failure")

	out.executeWithRetry(context.Background(), 1, func(ctx context.Context) error {
		return out.driver.Send(ctx, newTestEvent())
	})
	recovered := out.GetStatus()
	assert.Equal(t, "ok", recovered.Status)
	assert.Empty(t, recovered.LastError)
	assert.Equal(t, 1, recovered.FailedTotal)
	assert.Equal(t, 1, recovered.SentTotal)
}

func TestRetireGraceful(t *testing.T) {
	var calls atomic.Int64
	var closeCalled atomic.Bool

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			calls.Add(1)
			return nil
		},
		CloseFunc: func() error {
			closeCalled.Store(true)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()

	err := out.Retire(retireCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(5), calls.Load(), "all queued events must be processed")
	assert.True(t, closeCalled.Load(), "driver Close must be called")
}

func TestRetireCancelsWorkerContextAfterDrain(t *testing.T) {
	contexts := make(chan context.Context, 1)
	out := NewOutput(&testutil.MockDriver{
		DriverName: "retiring",
		SendFunc: func(ctx context.Context, _ *event.Event) error {
			contexts <- ctx
			return nil
		},
	}, defaultRuntimeDefaults(), nil)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	out.Start(parent)
	out.Enqueue(newTestEvent())
	retireCtx, retireCancel := context.WithTimeout(context.Background(), time.Second)
	defer retireCancel()
	require.NoError(t, out.Retire(retireCtx))
	workerCtx := <-contexts
	assert.ErrorIs(t, workerCtx.Err(), context.Canceled)
	assert.NoError(t, parent.Err(), "retiring one output must not cancel its parent")
}

func TestRetireDeadlineExceeded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		contexts := make(chan context.Context, 1)
		release := make(chan struct{})
		closed := make(chan struct{})
		out := NewOutput(&testutil.MockDriver{
			DriverName: "stuck",
			SendFunc: func(ctx context.Context, _ *event.Event) error {
				contexts <- ctx
				<-release
				return nil
			},
			CloseFunc: func() error {
				close(closed)
				return nil
			},
		}, defaultRuntimeDefaults(), nil)
		parent, cancel := context.WithCancel(context.Background())
		defer cancel()
		out.Start(parent)
		out.Enqueue(newTestEvent())
		workerCtx := <-contexts
		retireCtx, retireCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer retireCancel()
		start := time.Now()
		err := out.Retire(retireCtx)
		assert.ErrorContains(t, err, "deadline exceeded")
		assert.Equal(t, 50*time.Millisecond, time.Since(start))
		assert.ErrorIs(t, workerCtx.Err(), context.Canceled)
		assert.NoError(t, parent.Err())
		select {
		case <-closed:
			t.Error("driver closed before its send returned")
		default:
		}
		close(release)
		<-closed
	})
}

func TestRetireDoesNotCloseDriverBeforeWorkerExit(t *testing.T) {
	var mu sync.Mutex
	var closeOrder []string

	sendStarted := make(chan struct{})
	sendBlock := make(chan struct{})

	out := NewOutput(&testutil.MockDriver{
		DriverName: "ordered",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			close(sendStarted)
			<-sendBlock
			mu.Lock()
			closeOrder = append(closeOrder, "worker-exit")
			mu.Unlock()
			return nil
		},
		CloseFunc: func() error {
			mu.Lock()
			closeOrder = append(closeOrder, "driver-close")
			mu.Unlock()
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	out.Start(context.Background())
	out.Enqueue(newTestEvent())
	<-sendStarted

	// Retire with generous deadline so drain succeeds.
	retireDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		retireDone <- out.Retire(ctx)
	}()

	// Unblock the worker.
	close(sendBlock)

	err := <-retireDone
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, closeOrder, 2)
	assert.Equal(t, "worker-exit", closeOrder[0], "worker must exit before driver.Close is called")
	assert.Equal(t, "driver-close", closeOrder[1], "driver.Close must be called after worker exits")
}

func TestOutputDropsWhenQueueFull(t *testing.T) {
	blocked := make(chan struct{})
	cfg := defaultRuntimeDefaults()
	cfg.QueueSize = 2
	cfg.Workers = 1

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			<-blocked
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	assert.Greater(t, out.droppedTotal.Load(), int64(0))

	close(blocked)

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	_ = out.Retire(retireCtx)
}
