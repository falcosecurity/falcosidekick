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
	"fmt"
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
	requests int
	mu       sync.Mutex
}

func newRecordingMetrics() *recordingMetrics {
	return &recordingMetrics{statuses: map[string]int{}}
}

func (m *recordingMetrics) RecordOutput(_ context.Context, _, status string, events int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses[status] += int(events)
}

func (m *recordingMetrics) ObserveRequest(context.Context, string, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
}

func (m *recordingMetrics) snapshot() (statuses map[string]int, requests int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	statuses = make(map[string]int, len(m.statuses))
	for k, v := range m.statuses {
		statuses[k] = v
	}
	return statuses, m.requests
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
		cfg.Batching = &output.BatchingConfig{Enabled: new(true), BatchSize: 4, FlushInterval: time.Hour}
		return NewOutput(&testutil.MockBatchDriver{
			MockDriver: testutil.MockDriver{DriverName: "failing-batch"},
			SendBatchFunc: func(context.Context, []*event.Event) error {
				return errDelivery
			},
		}, cfg, metrics)
	})
}

// partialFailure names the events of a batch it rejected and those a retry may deliver.
type partialFailure struct {
	rejected, retryable []int
}

func (e partialFailure) Error() string          { return "part of the batch failed" }
func (e partialFailure) RejectedEvents() []int  { return e.rejected }
func (e partialFailure) RetryableEvents() []int { return e.retryable }

// scriptedSender answers each attempt with the next result and records the UUIDs it was given.
type scriptedSender struct {
	results  []error
	attempts [][]string
	mu       sync.Mutex
}

func (s *scriptedSender) send(events []*event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, len(events))
	for i, evt := range events {
		ids[i] = evt.UUID
	}
	s.attempts = append(s.attempts, ids)
	if len(s.attempts) > len(s.results) {
		return errors.New("attempt beyond the script")
	}
	return s.results[len(s.attempts)-1]
}

// everyAttempt answers err on each of the attempts retryingConfig allows.
func everyAttempt(err error) []error {
	results := make([]error, retryingConfig().Retry.MaxAttempts)
	for i := range results {
		results[i] = err
	}
	return results
}

// Only the retryable events are sent again, in batch order, and only they count against the circuit.
func TestPartialBatchFailure(t *testing.T) {
	ids := []string{"e0", "e1", "e2", "e3"}
	const partial = "part of the batch failed"
	wholeBatch := [][]string{ids, ids, ids}
	for _, tc := range []struct {
		name          string
		wantWarning   string
		wantLastError string
		wantStatus    Health
		wantKind      WarningKind
		results       []error
		wantAttempts  [][]string
		wantCircuit   CircuitState
		sent, failed  int
		threshold     int
		single        bool
		cancel        bool
	}{
		{
			name: "rejected only", results: []error{partialFailure{rejected: []int{1}}}, threshold: 1,
			wantAttempts: [][]string{ids}, sent: 3, failed: 1,
			wantStatus: HealthDegraded, wantKind: WarningDestination, wantWarning: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "retryable only, then delivered", results: []error{partialFailure{retryable: []int{2}}, nil},
			wantAttempts: [][]string{ids, {"e2"}}, sent: 4,
			wantStatus: HealthOK, wantCircuit: CircuitClosed,
		},
		{
			name: "retryable remainder counts against the circuit", threshold: 2,
			results:      []error{partialFailure{retryable: []int{2}}, partialFailure{retryable: []int{0}}},
			wantAttempts: [][]string{ids, {"e2"}}, sent: 3, failed: 1,
			wantStatus: HealthError, wantLastError: partial, wantCircuit: CircuitOpen,
		},
		{
			name: "mixed, remainder delivered", results: []error{partialFailure{rejected: []int{0}, retryable: []int{3}}, nil},
			wantAttempts: [][]string{ids, {"e3"}}, sent: 3, failed: 1,
			wantStatus: HealthDegraded, wantKind: WarningDestination, wantWarning: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "mixed twice, indexes into the remainder",
			results: []error{
				partialFailure{rejected: []int{1}, retryable: []int{3, 2}},
				partialFailure{rejected: []int{0}, retryable: []int{1}},
				nil,
			},
			wantAttempts: [][]string{ids, {"e2", "e3"}, {"e3"}}, sent: 2, failed: 2,
			wantStatus: HealthDegraded, wantKind: WarningDestination, wantWarning: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "remainder exhausted", results: []error{partialFailure{rejected: []int{0}, retryable: []int{2}}, errDelivery, errDelivery},
			wantAttempts: [][]string{ids, {"e2"}, {"e2"}}, sent: 2, failed: 2,
			wantStatus: HealthError, wantKind: WarningDestination, wantWarning: partial, wantLastError: errDelivery.Error(), wantCircuit: CircuitClosed,
		},
		{
			name: "remainder canceled during backoff", results: []error{partialFailure{rejected: []int{0}, retryable: []int{2}}}, cancel: true,
			wantAttempts: [][]string{ids}, sent: 2, failed: 2,
			wantStatus: HealthError, wantKind: WarningDestination, wantWarning: partial, wantLastError: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "both sets empty fail the batch", results: everyAttempt(partialFailure{}),
			wantAttempts: wholeBatch, failed: 4, wantStatus: HealthError, wantLastError: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "index out of range fails the batch", results: everyAttempt(partialFailure{rejected: []int{4}}),
			wantAttempts: wholeBatch, failed: 4, wantStatus: HealthError, wantLastError: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "negative index fails the batch", results: everyAttempt(partialFailure{retryable: []int{-1}}),
			wantAttempts: wholeBatch, failed: 4, wantStatus: HealthError, wantLastError: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "duplicate index fails the batch", results: everyAttempt(partialFailure{retryable: []int{1, 1}}),
			wantAttempts: wholeBatch, failed: 4, wantStatus: HealthError, wantLastError: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "overlapping sets fail the batch", results: everyAttempt(partialFailure{rejected: []int{1}, retryable: []int{1}}),
			wantAttempts: wholeBatch, failed: 4, wantStatus: HealthError, wantLastError: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "every event rejected fails the batch", results: everyAttempt(partialFailure{rejected: []int{0, 1, 2, 3}}),
			wantAttempts: wholeBatch, failed: 4, wantStatus: HealthError, wantLastError: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "every event retryable retries the batch", results: everyAttempt(partialFailure{retryable: []int{0, 1, 2, 3}}),
			wantAttempts: wholeBatch, failed: 4, wantStatus: HealthError, wantLastError: partial, wantCircuit: CircuitClosed,
		},
		{
			name: "single event is counted once", single: true, results: everyAttempt(partialFailure{rejected: []int{0}}),
			wantAttempts: [][]string{{"e0"}, {"e0"}, {"e0"}}, failed: 1, wantStatus: HealthError, wantLastError: partial, wantCircuit: CircuitClosed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := retryingConfig()
				cfg.Retry.InitialInterval, cfg.Retry.MaxInterval = time.Millisecond, time.Millisecond
				if tc.cancel {
					cfg.Retry.InitialInterval, cfg.Retry.MaxInterval = time.Hour, time.Hour
				}
				threshold := tc.threshold
				if threshold == 0 {
					threshold = 5
				}
				cfg.CircuitBreaker = &output.CircuitBreakerConfig{FailureThreshold: threshold, SuccessThreshold: 1, ResetTimeout: time.Hour}
				script := &scriptedSender{results: tc.results}
				base := testutil.MockDriver{
					DriverName: "partial",
					SendFunc:   func(_ context.Context, evt *event.Event) error { return script.send([]*event.Event{evt}) },
				}
				var driver output.Driver = &base
				count := 1
				if !tc.single {
					cfg.Batching = &output.BatchingConfig{Enabled: new(true), BatchSize: len(ids), FlushInterval: time.Hour}
					driver = &testutil.MockBatchDriver{
						MockDriver:    base,
						SendBatchFunc: func(_ context.Context, events []*event.Event) error { return script.send(events) },
					}
					count = len(ids)
				}
				metrics := newRecordingMetrics()
				out := NewOutput(driver, cfg, metrics)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				out.Start(ctx)
				for _, id := range ids[:count] {
					evt := newTestEvent()
					evt.UUID = id
					out.Enqueue(evt)
				}
				time.Sleep(time.Second)
				synctest.Wait()
				cancel()
				out.waitDone()

				status := out.GetStatus()
				assert.Equal(t, tc.wantAttempts, script.attempts, "each attempt sends exactly the events left")
				assert.Equal(t, tc.sent, status.SentTotal)
				assert.Equal(t, tc.failed, status.FailedTotal)
				assert.Zero(t, status.DroppedTotal)
				assert.Equal(t, tc.wantStatus, status.Status)
				assert.Equal(t, tc.wantKind, status.WarningKind)
				assert.Equal(t, tc.wantWarning, status.LastWarning)
				assert.Equal(t, tc.wantLastError, status.LastError)
				assert.Equal(t, tc.wantCircuit, out.circuitBreaker.GetState())
				statuses, requests := metrics.snapshot()
				assert.Equal(t, tc.sent, statuses["ok"], "output_events_total ok")
				assert.Equal(t, tc.failed, statuses["error"], "output_events_total error")
				assert.Equal(t, len(tc.wantAttempts), requests, "one duration per attempt")
			})
		})
	}
}

func TestRejectionWarningClearsOnCleanDelivery(t *testing.T) {
	out := NewOutput(&testutil.MockDriver{DriverName: "partial"}, defaultRuntimeDefaults(), nil)
	events := []*event.Event{newTestEvent(), newTestEvent()}
	out.executeWithRetry(context.Background(), events, func(context.Context, []*event.Event) error {
		return partialFailure{rejected: []int{0}}
	})
	status := out.GetStatus()
	require.Equal(t, HealthDegraded, status.Status)
	require.Equal(t, WarningDestination, status.WarningKind)

	out.executeWithRetry(context.Background(), events, func(context.Context, []*event.Event) error { return nil })
	status = out.GetStatus()
	assert.Equal(t, HealthOK, status.Status)
	assert.Empty(t, status.LastWarning)
	assert.Empty(t, status.WarningKind)
	assert.Equal(t, 3, status.SentTotal)
	assert.Equal(t, 1, status.FailedTotal)
}

// A batch still buffered when the workers stop was never attempted: it is dropped, not sent with a dead context.
func TestBatchBufferedOnCancelCountsAsDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := retryingConfig()
		cfg.Batching = &output.BatchingConfig{Enabled: new(true), BatchSize: 100, FlushInterval: time.Hour}
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
	batching := &output.BatchingConfig{Enabled: new(true), BatchSize: 3, FlushInterval: time.Hour}
	tests := []struct {
		batching    *output.BatchingConfig
		name        string
		deliverable int64
		deadline    bool
		partial     bool
	}{
		{name: "single drain", deliverable: submitted},
		{name: "batch drain", batching: batching, deliverable: submitted},
		{name: "batch drain with rejections", batching: batching, deliverable: submitted, partial: true},
		{name: "single deadline", deliverable: 2, deadline: true},
		{name: "batch deadline", batching: batching, deliverable: 2, deadline: true},
		{name: "batch deadline with rejections", batching: batching, deliverable: 2, deadline: true, partial: true},
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
				// A full batch has its first event rejected and its last one retried, alone.
				deliverBatch := func(ctx context.Context, events []*event.Event) error {
					if err := deliver(ctx); err != nil || !tt.partial || len(events) < batching.BatchSize {
						return err
					}
					return partialFailure{rejected: []int{0}, retryable: []int{len(events) - 1}}
				}
				closed := make(chan struct{})
				cfg := retryingConfig()
				if tt.partial {
					cfg.Retry.InitialInterval, cfg.Retry.MaxInterval = time.Millisecond, time.Millisecond
				}
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
					driver = &testutil.MockBatchDriver{MockDriver: base, SendBatchFunc: deliverBatch}
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
				if tt.partial {
					// 20 events over two workers make six full batches, each with one rejection.
					assert.Equal(t, 6, status.FailedTotal)
					assert.Equal(t, submitted-6, status.SentTotal)
					return
				}
				assert.Equal(t, submitted, status.SentTotal)
			})
		})
	}
}

// output_request_duration_seconds observes every attempt, while output_events_total counts each
// event once, by its final outcome.
func TestEveryAttemptIsObserved(t *testing.T) {
	permanent := fmt.Errorf("rejected: %w", output.ErrPermanent)
	tests := []struct {
		wantStatuses map[string]int
		name         string
		results      []error
		wantRequests int
	}{
		{name: "success", results: []error{nil}, wantRequests: 1, wantStatuses: map[string]int{"ok": 1}},
		{name: "fails then succeeds", results: []error{errDelivery, errDelivery, nil}, wantRequests: 3, wantStatuses: map[string]int{"ok": 1}},
		{name: "every attempt fails", results: []error{errDelivery, errDelivery, errDelivery}, wantRequests: 3, wantStatuses: map[string]int{"error": 1}},
		{name: "permanent failure is not retried", results: []error{permanent}, wantRequests: 1, wantStatuses: map[string]int{"error": 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var attempts atomic.Int64
				metrics := newRecordingMetrics()
				out := NewOutput(&testutil.MockDriver{
					DriverName: "flaky",
					SendFunc: func(context.Context, *event.Event) error {
						return tt.results[attempts.Add(1)-1]
					},
				}, retryingConfig(), metrics)
				out.Start(context.Background())
				out.Enqueue(newTestEvent())

				ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
				defer cancel()
				require.NoError(t, out.Retire(ctx))

				statuses, requests := metrics.snapshot()
				assert.EqualValues(t, len(tt.results), attempts.Load())
				assert.Equal(t, tt.wantRequests, requests, "one duration per attempt")
				assert.Equal(t, tt.wantStatuses, statuses, "one count per event")
			})
		})
	}
}

func TestBatchWorkerSendsNothingAfterCancellation(t *testing.T) {
	// The worker select picks randomly between cancellation and a ready queue.
	for range 50 {
		synctest.Test(t, func(t *testing.T) {
			cfg := retryingConfig()
			cfg.Batching = &output.BatchingConfig{Enabled: new(true), BatchSize: 1, FlushInterval: time.Hour}
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
