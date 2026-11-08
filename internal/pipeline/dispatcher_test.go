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
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func defaultRuntimeDefaults() *output.RuntimeConfig {
	return &output.RuntimeConfig{
		QueueSize: 100,
		Workers:   1,
		Retry: &output.RetryConfig{
			MaxAttempts:     1,
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     100 * time.Millisecond,
			Multiplier:      2.0,
		},
		CircuitBreaker: &output.CircuitBreakerConfig{
			FailureThreshold: 5,
			SuccessThreshold: 2,
			ResetTimeout:     30 * time.Second,
		},
	}
}

func TestDispatcherRoutesToCorrectOutputs(t *testing.T) {
	var slackCalls, lokiCalls atomic.Int64

	slackCfg := defaultRuntimeDefaults()
	slackCfg.MinPriority = event.PriorityCritical
	slackOut := NewOutput(&testutil.MockDriver{DriverName: "slack", SendFunc: func(_ context.Context, _ *event.Event) error {
		slackCalls.Add(1)
		return nil
	}}, slackCfg, nil)

	lokiCfg := defaultRuntimeDefaults()
	lokiCfg.MinPriority = event.PriorityDebug
	lokiOut := NewOutput(&testutil.MockDriver{DriverName: "loki", SendFunc: func(_ context.Context, _ *event.Event) error {
		lokiCalls.Add(1)
		return nil
	}}, lokiCfg, nil)

	d := NewDispatcher([]*Output{slackOut, lokiOut})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	evt := newTestEvent()
	evt.Priority = event.PriorityWarning
	d.DispatchEvent(evt)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	err := d.Shutdown(shutdownCtx, stopWorkers)
	require.NoError(t, err)

	assert.Equal(t, int64(0), slackCalls.Load(), "warning evt must not reach critical-only slack")
	assert.Equal(t, int64(1), lokiCalls.Load(), "warning evt must reach debug-level loki")
}

func TestDispatcherCollectStatus(t *testing.T) {
	d := NewDispatcher([]*Output{
		NewOutput(&testutil.MockDriver{DriverName: "slack"}, defaultRuntimeDefaults(), nil),
		NewOutput(&testutil.MockDriver{DriverName: "loki"}, defaultRuntimeDefaults(), nil),
	})

	statuses := d.CollectStatus()
	assert.Len(t, statuses, 2)

	names := make(map[string]bool)
	for _, s := range statuses {
		names[s.Name] = true
	}
	assert.True(t, names["slack"])
	assert.True(t, names["loki"])
}

func TestDispatcherDrainQueues(t *testing.T) {
	var mu sync.Mutex
	var received []string

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, evt *event.Event) error {
			mu.Lock()
			received = append(received, evt.Rule)
			mu.Unlock()
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	d := NewDispatcher([]*Output{out})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	for i := 0; i < 10; i++ {
		e := newTestEvent()
		e.Rule = fmt.Sprintf("rule-%d", i)
		d.DispatchEvent(e)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	err := d.Shutdown(shutdownCtx, stopWorkers)
	require.NoError(t, err)

	mu.Lock()
	assert.Len(t, received, 10)
	mu.Unlock()
}

func TestDispatcherConcurrentDispatch(t *testing.T) {
	var count atomic.Int64

	cfg := defaultRuntimeDefaults()
	cfg.Workers = 4

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			count.Add(1)
			return nil
		},
	}, cfg, nil)

	d := NewDispatcher([]*Output{out})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.DispatchEvent(newTestEvent())
		}()
	}
	wg.Wait()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	err := d.Shutdown(shutdownCtx, stopWorkers)
	require.NoError(t, err)

	require.Equal(t, int64(100), count.Load())
}

func TestDrainQueuesWaitsForActiveSend(t *testing.T) {
	sendStarted := make(chan struct{})
	sendBlock := make(chan struct{})
	var sendCompleted atomic.Bool

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			close(sendStarted)
			<-sendBlock
			sendCompleted.Store(true)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	d := NewDispatcher([]*Output{out})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	d.DispatchEvent(newTestEvent())
	<-sendStarted

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownDone <- d.Shutdown(ctx, stopWorkers)
	}()

	time.Sleep(100 * time.Millisecond)
	select {
	case <-shutdownDone:
		t.Fatal("Shutdown returned while Send was still active")
	default:
	}

	close(sendBlock)

	select {
	case err := <-shutdownDone:
		require.NoError(t, err)
		assert.True(t, sendCompleted.Load(), "Send must complete before Shutdown returns")
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after Send completed")
	}
}

func TestDispatcherShutdownBoundedWithStuckSender(t *testing.T) {
	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(ctx context.Context, _ *event.Event) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}, defaultRuntimeDefaults(), nil)

	d := NewDispatcher([]*Output{out})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	d.DispatchEvent(newTestEvent())
	time.Sleep(20 * time.Millisecond)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer shutdownCancel()

	start := time.Now()
	err := d.Shutdown(shutdownCtx, stopWorkers)
	elapsed := time.Since(start)

	assert.Error(t, err, "Shutdown must return error when deadline exceeded with stuck worker")
	assert.Less(t, elapsed, 1*time.Second, "Shutdown must complete within deadline, not hang forever")
}

// --- Hot-reload lifecycle tests ---

func TestAddOutputRoutesEvents(t *testing.T) {
	var origCalls, addedCalls atomic.Int64

	origOut := NewOutput(&testutil.MockDriver{
		DriverName: "original",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			origCalls.Add(1)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	d := NewDispatcher([]*Output{origOut})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	// Add new output while pipeline is running.
	addedOut := NewOutput(&testutil.MockDriver{
		DriverName: "added",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			addedCalls.Add(1)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)
	err := d.AddOutput(workerRunCtx, addedOut)
	require.NoError(t, err)

	d.DispatchEvent(newTestEvent())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, d.Shutdown(shutdownCtx, stopWorkers))

	assert.Equal(t, int64(1), origCalls.Load(), "original output must receive event")
	assert.Equal(t, int64(1), addedCalls.Load(), "dynamically added output must receive event")
}

func TestRemoveOutputDrainsAndStops(t *testing.T) {
	var calls atomic.Int64
	var closeCalled atomic.Bool

	out := NewOutput(&testutil.MockDriver{
		DriverName: "removable",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			calls.Add(1)
			return nil
		},
		CloseFunc: func() error {
			closeCalled.Store(true)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	d := NewDispatcher([]*Output{out})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	// Dispatch one event, let it process.
	d.DispatchEvent(newTestEvent())
	time.Sleep(50 * time.Millisecond)

	// Remove output.
	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := d.RemoveOutput(retireCtx, "removable")
	require.NoError(t, err)

	assert.True(t, closeCalled.Load(), "driver Close must be called after drain")
	assert.Equal(t, int64(1), calls.Load())

	// Dispatch another event after removal - should not reach removed output.
	remaining := NewOutput(&testutil.MockDriver{DriverName: "remaining"}, defaultRuntimeDefaults(), nil)
	require.NoError(t, d.AddOutput(workerRunCtx, remaining))

	d.DispatchEvent(newTestEvent())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, d.Shutdown(shutdownCtx, stopWorkers))

	assert.Equal(t, int64(1), calls.Load(), "removed output must not receive further events")
}

func TestRemoveOutputNonexistent(t *testing.T) {
	d := NewDispatcher(nil)
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer retireCancel()
	err := d.RemoveOutput(retireCtx, "does-not-exist")
	require.NoError(t, err)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer shutdownCancel()
	require.NoError(t, d.Shutdown(shutdownCtx, stopWorkers))
}

func TestReplaceOutputSwapsAtomically(t *testing.T) {
	var oldCalls, newCalls atomic.Int64
	var oldClosed atomic.Bool

	oldOut := NewOutput(&testutil.MockDriver{
		DriverName: "target",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			oldCalls.Add(1)
			return nil
		},
		CloseFunc: func() error {
			oldClosed.Store(true)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	d := NewDispatcher([]*Output{oldOut})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	// Let one event go to old.
	d.DispatchEvent(newTestEvent())
	time.Sleep(50 * time.Millisecond)

	// Replace with new output.
	replacement := NewOutput(&testutil.MockDriver{
		DriverName: "target",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			newCalls.Add(1)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := d.ReplaceOutput(retireCtx, workerRunCtx, "target", replacement)
	require.NoError(t, err)

	// Events after replace go to new output.
	d.DispatchEvent(newTestEvent())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, d.Shutdown(shutdownCtx, stopWorkers))

	assert.Equal(t, int64(1), oldCalls.Load(), "old output must have received first event")
	assert.Equal(t, int64(1), newCalls.Load(), "new output must have received second event")
	assert.True(t, oldClosed.Load(), "old driver must be closed after drain")
}

func TestReplaceOutputNonexistent(t *testing.T) {
	var calls atomic.Int64

	d := NewDispatcher(nil)
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	newOut := NewOutput(&testutil.MockDriver{
		DriverName: "fresh",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			calls.Add(1)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer retireCancel()
	err := d.ReplaceOutput(retireCtx, workerRunCtx, "fresh", newOut)
	require.NoError(t, err)

	d.DispatchEvent(newTestEvent())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, d.Shutdown(shutdownCtx, stopWorkers))

	assert.Equal(t, int64(1), calls.Load(), "replacing non-existent name should still add output")
}

func TestDispatcherShutdownRejectsConcurrentDispatchAfterStop(t *testing.T) {
	var calls atomic.Int64

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			calls.Add(1)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	d := NewDispatcher([]*Output{out})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	err := d.Shutdown(shutdownCtx, stopWorkers)
	require.NoError(t, err)

	// Dispatch after shutdown must not panic or enqueue.
	callsBefore := calls.Load()
	d.DispatchEvent(newTestEvent())
	assert.Equal(t, callsBefore, calls.Load(), "dispatch after shutdown must be silently dropped")
}

func TestDispatcherLifecycleMutationRejectedAfterStop(t *testing.T) {
	d := NewDispatcher(nil)
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer shutdownCancel()
	require.NoError(t, d.Shutdown(shutdownCtx, stopWorkers))

	newOut := NewOutput(&testutil.MockDriver{DriverName: "late"}, defaultRuntimeDefaults(), nil)

	assert.ErrorIs(t, d.AddOutput(workerRunCtx, newOut), ErrDispatcherStopped)

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer retireCancel()
	assert.ErrorIs(t, d.RemoveOutput(retireCtx, "anything"), ErrDispatcherStopped)
	assert.ErrorIs(t, d.ReplaceOutput(retireCtx, workerRunCtx, "anything", newOut), ErrDispatcherStopped)
}

func TestDispatcherShutdownAfterReload(t *testing.T) {
	var startupClosed, replacementClosed, addedClosed atomic.Int64

	startupOut := NewOutput(&testutil.MockDriver{
		DriverName: "original",
		CloseFunc:  func() error { startupClosed.Add(1); return nil },
	}, defaultRuntimeDefaults(), nil)

	d := NewDispatcher([]*Output{startupOut})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	// Reload: replace "original" and add "extra".
	replacement := NewOutput(&testutil.MockDriver{
		DriverName: "original",
		CloseFunc:  func() error { replacementClosed.Add(1); return nil },
	}, defaultRuntimeDefaults(), nil)

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	require.NoError(t, d.ReplaceOutput(retireCtx, workerRunCtx, "original", replacement))

	extra := NewOutput(&testutil.MockDriver{
		DriverName: "extra",
		CloseFunc:  func() error { addedClosed.Add(1); return nil },
	}, defaultRuntimeDefaults(), nil)
	require.NoError(t, d.AddOutput(workerRunCtx, extra))

	// Shutdown closes current live outputs (replacement and extra), not stale startup.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, d.Shutdown(shutdownCtx, stopWorkers))

	// The startup "original" was already retired by ReplaceOutput (Retire).
	assert.Equal(t, int64(1), startupClosed.Load(), "retired startup output must be closed exactly once by Retire")

	// The replacement and the added output must be closed exactly once by Shutdown.
	assert.Equal(t, int64(1), replacementClosed.Load(), "replacement output must be closed once by Shutdown")
	assert.Equal(t, int64(1), addedClosed.Load(), "added output must be closed once by Shutdown")
}

func TestGetReadableStoreFound(t *testing.T) {
	store := &mockReadableStoreDriver{
		MockDriver: testutil.MockDriver{DriverName: "inmemory"},
	}

	out := NewOutput(store, defaultRuntimeDefaults(), nil)
	d := NewDispatcher([]*Output{out})

	rs, ok := d.GetReadableStore("inmemory")
	assert.True(t, ok)
	assert.NotNil(t, rs)
}

func TestGetReadableStoreNotReadable(t *testing.T) {
	out := NewOutput(&testutil.MockDriver{DriverName: "slack"}, defaultRuntimeDefaults(), nil)
	d := NewDispatcher([]*Output{out})

	rs, ok := d.GetReadableStore("slack")
	assert.False(t, ok)
	assert.Nil(t, rs)
}

func TestGetReadableStoreNotFound(t *testing.T) {
	d := NewDispatcher(nil)

	rs, ok := d.GetReadableStore("missing")
	assert.False(t, ok)
	assert.Nil(t, rs)
}

func TestOutputNames(t *testing.T) {
	d := NewDispatcher([]*Output{
		NewOutput(&testutil.MockDriver{DriverName: "a"}, defaultRuntimeDefaults(), nil),
		NewOutput(&testutil.MockDriver{DriverName: "b"}, defaultRuntimeDefaults(), nil),
	})

	names := d.OutputNames()
	assert.Len(t, names, 2)
	assert.ElementsMatch(t, []string{"a", "b"}, names)
}

func TestConcurrentDispatchAndLifecycle(t *testing.T) {
	var total atomic.Int64

	d := NewDispatcher([]*Output{
		NewOutput(&testutil.MockDriver{
			DriverName: "base",
			SendFunc: func(_ context.Context, _ *event.Event) error {
				total.Add(1)
				return nil
			},
		}, defaultRuntimeDefaults(), nil),
	})
	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	d.Start(workerRunCtx)

	// Concurrent dispatch.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.DispatchEvent(newTestEvent())
		}()
	}

	// Concurrent add/remove cycle.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			name := fmt.Sprintf("dynamic-%d", i)
			out := NewOutput(&testutil.MockDriver{
				DriverName: name,
				SendFunc: func(_ context.Context, _ *event.Event) error {
					total.Add(1)
					return nil
				},
			}, defaultRuntimeDefaults(), nil)
			_ = d.AddOutput(workerRunCtx, out)

			retireCtx, retireCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			_ = d.RemoveOutput(retireCtx, name)
			retireCancel()
		}
	}()

	wg.Wait()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, d.Shutdown(shutdownCtx, stopWorkers))

	// Base output must have processed at least some events.
	assert.Greater(t, total.Load(), int64(0))
}

// mockReadableStoreDriver implements both output.Driver and output.ReadableStore.
type mockReadableStoreDriver struct {
	testutil.MockDriver
}

func (m *mockReadableStoreDriver) Search(_ context.Context, _ *output.SearchQuery) (*output.SearchResult, error) {
	return &output.SearchResult{}, nil
}

func (m *mockReadableStoreDriver) Count(_ context.Context, _ *output.Filters) (int64, error) {
	return 0, nil
}

func (m *mockReadableStoreDriver) CountBy(_ context.Context, _ string, _ *output.Filters) (map[string]int64, error) {
	return nil, nil
}

func (m *mockReadableStoreDriver) Histogram(_ context.Context, _ *output.HistogramRequest) (*output.HistogramResult, error) {
	return &output.HistogramResult{}, nil
}

func (m *mockReadableStoreDriver) GetEvent(_ context.Context, _ string) (*event.Event, error) {
	return nil, nil
}
