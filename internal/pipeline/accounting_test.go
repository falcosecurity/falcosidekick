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

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

var errDelivery = errors.New("delivery failed")

type recordingMetrics struct {
	core.MetricsCollector
	statuses map[string]int
	drops    int
	mu       sync.Mutex
}

func newRecordingMetrics() *recordingMetrics {
	return &recordingMetrics{statuses: map[string]int{}}
}

func (m *recordingMetrics) RecordOutput(_ context.Context, _, status string, events int64, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses[status] += int(events)
}

func (m *recordingMetrics) RecordDrop(_ context.Context, _ string, events int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drops += int(events)
}

func retryingConfig() *output.RuntimeConfig {
	cfg := defaultRuntimeDefaults()
	cfg.Retry = &output.RetryConfig{
		MaxAttempts:     3,
		InitialInterval: time.Hour,
		MaxInterval:     time.Hour,
		Multiplier:      1,
	}
	return cfg
}

func cancelledBackoffCase(t *testing.T, enqueue int, newOutput func(*recordingMetrics) *Output) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		metrics := newRecordingMetrics()
		out := newOutput(metrics)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out.Start(ctx)
		for range enqueue {
			out.Enqueue(newTestEvent())
		}
		synctest.Wait()

		cancel()
		out.waitDone()

		status := out.GetStatus()
		assert.Equal(t, enqueue, status.FailedTotal)
		assert.Zero(t, status.DroppedTotal)
		assert.Equal(t, errDelivery.Error(), status.LastError)
		assert.Equal(t, enqueue, metrics.statuses["error"], "output_events_total counts events, a batch included")
		assert.Zero(t, metrics.drops)
	})
}

func TestCancelledBackoffCountsEventAsFailed(t *testing.T) {
	cancelledBackoffCase(t, 1, func(metrics *recordingMetrics) *Output {
		return NewOutput(&testutil.MockDriver{
			DriverName: "failing",
			SendFunc: func(context.Context, *event.Event) error {
				return errDelivery
			},
		}, retryingConfig(), metrics)
	})
}

func TestCancelledBackoffCountsWholeBatchAsFailed(t *testing.T) {
	cancelledBackoffCase(t, 4, func(metrics *recordingMetrics) *Output {
		cfg := retryingConfig()
		cfg.Batching = &output.BatchingConfig{Enabled: true, BatchSize: 4, FlushInterval: time.Hour}
		return NewOutput(&testutil.MockBatchDriver{
			MockDriver: testutil.MockDriver{DriverName: "failing-batch"},
			SendBatchFunc: func(context.Context, []*event.Event) error {
				return errDelivery
			},
		}, cfg, metrics)
	})
}

// A batch still buffered when the workers stop was never attempted: it is dropped, not sent with a dead context.
func TestBatchBufferedOnCancelCountsAsDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := retryingConfig()
		cfg.Batching = &output.BatchingConfig{Enabled: true, BatchSize: 100, FlushInterval: time.Hour}
		var sends atomic.Int32
		out := NewOutput(&testutil.MockBatchDriver{
			MockDriver: testutil.MockDriver{DriverName: "buffered"},
			SendBatchFunc: func(ctx context.Context, _ []*event.Event) error {
				sends.Add(1)
				return ctx.Err()
			},
		}, cfg, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		out.Start(ctx)
		for range 4 {
			out.Enqueue(newTestEvent())
		}
		synctest.Wait()

		cancel()
		out.waitDone()

		status := out.GetStatus()
		assert.Zero(t, sends.Load())
		assert.Equal(t, 4, status.DroppedTotal)
		assert.Zero(t, status.FailedTotal)
		assert.Empty(t, status.LastError)
	})
}

func stuckDriver(closed chan struct{}) *testutil.MockDriver {
	return &testutil.MockDriver{
		DriverName: "stuck",
		SendFunc: func(ctx context.Context, _ *event.Event) error {
			<-ctx.Done()
			return ctx.Err()
		},
		CloseFunc: func() error {
			close(closed)
			return nil
		},
	}
}

func assertOneFailedRestDropped(t *testing.T, out *Output, metrics *recordingMetrics, dropped int) {
	t.Helper()
	status := out.GetStatus()
	assert.Equal(t, 1, status.FailedTotal)
	assert.Equal(t, dropped, status.DroppedTotal)
	assert.Equal(t, context.Canceled.Error(), status.LastError)
	assert.Equal(t, 1, metrics.statuses["error"])
	assert.Equal(t, dropped, metrics.drops)
}

func TestRetireDeadlineCountsQueuedEventsAsDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		closed := make(chan struct{})
		metrics := newRecordingMetrics()
		out := NewOutput(stuckDriver(closed), retryingConfig(), metrics)
		out.Start(context.Background())
		for range 4 {
			out.Enqueue(newTestEvent())
		}
		synctest.Wait()

		retireCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.Error(t, out.Retire(retireCtx))
		<-closed

		assertOneFailedRestDropped(t, out, metrics, 3)
	})
}

func TestShutdownDeadlineCountsQueuedEventsAsDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		closed := make(chan struct{})
		metrics := newRecordingMetrics()
		out := NewOutput(stuckDriver(closed), retryingConfig(), metrics)
		dispatcher := NewDispatcher([]*Output{out})
		workerCtx, stopWorkers := context.WithCancel(context.Background())
		defer stopWorkers()
		dispatcher.Start(workerCtx)
		for range 4 {
			out.Enqueue(newTestEvent())
		}
		synctest.Wait()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.ErrorIs(t, dispatcher.Shutdown(shutdownCtx, stopWorkers), context.DeadlineExceeded)
		<-closed

		assertOneFailedRestDropped(t, out, metrics, 3)
	})
}

func TestEveryAcceptedEventReachesExactlyOneCounter(t *testing.T) {
	const submitted = 20
	batching := &output.BatchingConfig{Enabled: true, BatchSize: 3, FlushInterval: time.Hour}
	tests := []struct {
		batching    *output.BatchingConfig
		name        string
		deliverable int64
		deadline    bool
	}{
		{name: "single drain", deliverable: submitted},
		{name: "batch drain", batching: batching, deliverable: submitted},
		{name: "single deadline", deliverable: 2, deadline: true},
		{name: "batch deadline", batching: batching, deliverable: 2, deadline: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var delivered atomic.Int64
				deliver := func(ctx context.Context) error {
					if delivered.Add(1) <= tt.deliverable {
						return nil
					}
					<-ctx.Done()
					return ctx.Err()
				}
				closed := make(chan struct{})
				cfg := retryingConfig()
				cfg.Workers = 2
				cfg.QueueSize = submitted
				if tt.deadline {
					cfg.QueueSize = 12
				}
				cfg.Batching = tt.batching
				base := testutil.MockDriver{
					DriverName: "mixed",
					SendFunc: func(ctx context.Context, _ *event.Event) error {
						return deliver(ctx)
					},
					CloseFunc: func() error {
						close(closed)
						return nil
					},
				}
				var driver output.Driver = &base
				if tt.batching != nil {
					driver = &testutil.MockBatchDriver{
						MockDriver: base,
						SendBatchFunc: func(ctx context.Context, _ []*event.Event) error {
							return deliver(ctx)
						},
					}
				}
				out := NewOutput(driver, cfg, nil)
				out.Start(context.Background())
				for range submitted {
					out.Enqueue(newTestEvent())
				}

				retireCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				err := out.Retire(retireCtx)
				<-closed

				status := out.GetStatus()
				assert.Equal(t, submitted, status.SentTotal+status.FailedTotal+status.DroppedTotal)
				assert.Zero(t, status.QueueDepth)
				if tt.deadline {
					require.Error(t, err)
					assert.Positive(t, status.FailedTotal)
					assert.Positive(t, status.DroppedTotal)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, submitted, status.SentTotal)
			})
		})
	}
}

func TestBatchWorkerSendsNothingAfterCancellation(t *testing.T) {
	// The worker select picks randomly between cancellation and a ready queue.
	for range 50 {
		synctest.Test(t, func(t *testing.T) {
			cfg := retryingConfig()
			cfg.Batching = &output.BatchingConfig{Enabled: true, BatchSize: 1, FlushInterval: time.Hour}
			var sends atomic.Int32
			out := NewOutput(&testutil.MockBatchDriver{
				MockDriver: testutil.MockDriver{DriverName: "stuck-batch"},
				SendBatchFunc: func(ctx context.Context, _ []*event.Event) error {
					sends.Add(1)
					<-ctx.Done()
					return ctx.Err()
				},
			}, cfg, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out.Start(ctx)
			for range 4 {
				out.Enqueue(newTestEvent())
			}
			synctest.Wait()

			cancel()
			out.waitDone()

			status := out.GetStatus()
			assert.Equal(t, int32(1), sends.Load())
			assert.Equal(t, 1, status.FailedTotal)
			assert.Equal(t, 3, status.DroppedTotal)
		})
	}
}
