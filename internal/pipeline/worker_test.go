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
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func batchRuntimeDefaults(batchSize int, flushInterval time.Duration) *output.RuntimeConfig {
	cfg := defaultRuntimeDefaults()
	cfg.Batching = &output.BatchingConfig{
		Enabled:       true,
		BatchSize:     batchSize,
		FlushInterval: flushInterval,
	}
	return cfg
}

func TestBatchWorkerFlushOnSize(t *testing.T) {
	var mu sync.Mutex
	var batches []int

	cfg := batchRuntimeDefaults(5, 10*time.Second)
	out := NewOutput(&testutil.MockBatchDriver{
		MockDriver: testutil.MockDriver{DriverName: "batch-test"},
		SendBatchFunc: func(_ context.Context, events []*event.Event) error {
			mu.Lock()
			batches = append(batches, len(events))
			mu.Unlock()
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 10; i++ {
		out.Enqueue(newTestEvent())
	}

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, batches)
	total := 0
	for _, b := range batches {
		assert.LessOrEqual(t, b, 5, "batch must not exceed configured size")
		total += b
	}
	assert.Equal(t, 10, total, "all events must be delivered")
}

func TestBatchWorkerFlushOnInterval(t *testing.T) {
	var mu sync.Mutex
	var batches []int

	cfg := batchRuntimeDefaults(100, 50*time.Millisecond)
	out := NewOutput(&testutil.MockBatchDriver{
		MockDriver: testutil.MockDriver{DriverName: "batch-test"},
		SendBatchFunc: func(_ context.Context, events []*event.Event) error {
			mu.Lock()
			batches = append(batches, len(events))
			mu.Unlock()
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 3; i++ {
		out.Enqueue(newTestEvent())
	}

	time.Sleep(150 * time.Millisecond)

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, batches, "timer must trigger flush before queue close")
	total := 0
	for _, b := range batches {
		total += b
	}
	assert.Equal(t, 3, total)
}

func TestBatchWorkerFlushOnClose(t *testing.T) {
	var mu sync.Mutex
	var batches []int

	cfg := batchRuntimeDefaults(100, 10*time.Second)
	out := NewOutput(&testutil.MockBatchDriver{
		MockDriver: testutil.MockDriver{DriverName: "batch-test"},
		SendBatchFunc: func(_ context.Context, events []*event.Event) error {
			mu.Lock()
			batches = append(batches, len(events))
			mu.Unlock()
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 3; i++ {
		out.Enqueue(newTestEvent())
	}

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, batches, "remaining events must be flushed on queue close")
	total := 0
	for _, b := range batches {
		total += b
	}
	assert.Equal(t, 3, total)
}

func TestBatchWorkerContextCancel(t *testing.T) {
	var mu sync.Mutex
	var batches []int

	cfg := batchRuntimeDefaults(100, 10*time.Second)
	out := NewOutput(&testutil.MockBatchDriver{
		MockDriver: testutil.MockDriver{DriverName: "batch-test"},
		SendBatchFunc: func(_ context.Context, events []*event.Event) error {
			mu.Lock()
			batches = append(batches, len(events))
			mu.Unlock()
			return nil
		},
	}, cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	out.Start(ctx)

	for i := 0; i < 3; i++ {
		out.Enqueue(newTestEvent())
	}
	time.Sleep(20 * time.Millisecond)

	cancel()
	out.waitDone()

	mu.Lock()
	defer mu.Unlock()
	total := 0
	for _, b := range batches {
		total += b
	}
	assert.Equal(t, 3, total, "buffered events must be flushed on context cancel")
}

func TestBatchWorkerDisabledFallsBackToSingle(t *testing.T) {
	var singleCalls atomic.Int64
	var batchCalls atomic.Int64

	cfg := defaultRuntimeDefaults()
	cfg.Batching = &output.BatchingConfig{Enabled: false, BatchSize: 5, FlushInterval: time.Second}

	out := NewOutput(&testutil.MockBatchDriver{
		MockDriver: testutil.MockDriver{
			DriverName: "batch-test",
			SendFunc: func(_ context.Context, _ *event.Event) error {
				singleCalls.Add(1)
				return nil
			},
		},
		SendBatchFunc: func(_ context.Context, _ []*event.Event) error {
			batchCalls.Add(1)
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(5), singleCalls.Load(), "disabled batching must use single Send")
	assert.Equal(t, int64(0), batchCalls.Load(), "SendBatch must not be called when disabled")
}

func TestBatchWorkerNonBatchDriver(t *testing.T) {
	var singleCalls atomic.Int64

	cfg := defaultRuntimeDefaults()
	cfg.Batching = &output.BatchingConfig{Enabled: true, BatchSize: 5, FlushInterval: time.Second}

	out := NewOutput(&testutil.MockDriver{
		DriverName: "non-batch",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			singleCalls.Add(1)
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(5), singleCalls.Load(), "non-BatchSender driver must use single Send")
}

func TestBatchWorkerRetryOnFailure(t *testing.T) {
	var attempts atomic.Int64

	cfg := batchRuntimeDefaults(5, 10*time.Second)
	cfg.Retry = &output.RetryConfig{
		MaxAttempts:     3,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     50 * time.Millisecond,
		Multiplier:      2.0,
	}

	out := NewOutput(&testutil.MockBatchDriver{
		MockDriver: testutil.MockDriver{DriverName: "batch-test"},
		SendBatchFunc: func(_ context.Context, _ []*event.Event) error {
			n := attempts.Add(1)
			if n <= 2 {
				return fmt.Errorf("transient error")
			}
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 5; i++ {
		out.Enqueue(newTestEvent())
	}

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(3), attempts.Load(), "batch must be retried")
	assert.Equal(t, int64(5), out.sentTotal.Load(), "all events in batch counted on success")
}

func TestWorkerSendsEvent(t *testing.T) {
	var received atomic.Int64
	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			received.Add(1)
			return nil
		},
	}, defaultRuntimeDefaults(), nil)

	ctx := context.Background()
	out.Start(ctx)
	out.Enqueue(newTestEvent())

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(1), received.Load())
	assert.Equal(t, int64(1), out.sentTotal.Load())
}

func TestWorkerRetriesOnFailure(t *testing.T) {
	var attempts atomic.Int64
	cfg := defaultRuntimeDefaults()
	cfg.Retry = &output.RetryConfig{
		MaxAttempts:     4,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     50 * time.Millisecond,
		Multiplier:      2.0,
	}

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			n := attempts.Add(1)
			if n <= 2 {
				return fmt.Errorf("transient error")
			}
			return nil
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)
	out.Enqueue(newTestEvent())

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(3), attempts.Load())
	assert.Equal(t, int64(1), out.sentTotal.Load())
}

func TestWorkerFailsAfterMaxRetries(t *testing.T) {
	cfg := defaultRuntimeDefaults()
	cfg.Retry = &output.RetryConfig{
		MaxAttempts:     2,
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     10 * time.Millisecond,
		Multiplier:      1.0,
	}

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			return fmt.Errorf("persistent error")
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)
	out.Enqueue(newTestEvent())

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(0), out.sentTotal.Load())
	assert.Equal(t, int64(1), out.failedTotal.Load())
	assert.Contains(t, out.lastError.Load().(string), "persistent error")
}

func TestWorkerCircuitBreakerBlocks(t *testing.T) {
	var attempts atomic.Int64
	cfg := defaultRuntimeDefaults()
	cfg.Workers = 1
	cfg.QueueSize = 100
	cfg.Retry = &output.RetryConfig{
		MaxAttempts:     1,
		InitialInterval: 1 * time.Millisecond,
		MaxInterval:     1 * time.Millisecond,
		Multiplier:      1.0,
	}
	cfg.CircuitBreaker = &output.CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		ResetTimeout:     5 * time.Second,
	}

	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			attempts.Add(1)
			return fmt.Errorf("fail")
		},
	}, cfg, nil)

	ctx := context.Background()
	out.Start(ctx)

	for i := 0; i < 10; i++ {
		out.Enqueue(newTestEvent())
	}

	retireCtx, retireCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retireCancel()
	err := out.Retire(retireCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(2), attempts.Load())
	assert.Equal(t, CircuitOpen, out.circuitBreaker.GetState())
}

func TestWorkerForceStopOnContextCancel(t *testing.T) {
	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(ctx context.Context, _ *event.Event) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}, defaultRuntimeDefaults(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	out.Start(ctx)

	out.Enqueue(newTestEvent())
	time.Sleep(20 * time.Millisecond)

	cancel()
	out.waitDone()
}

func TestWorkerRetriesRequireCircuitAdmission(t *testing.T) {
	for _, batchSize := range []int{1, 3} {
		for _, threshold := range []int{1, 2} {
			t.Run(fmt.Sprintf("batch_%d_threshold_%d", batchSize, threshold), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					cfg := batchRuntimeDefaults(batchSize, time.Second)
					cfg.Batching.Enabled = batchSize > 1
					cfg.Retry.MaxAttempts = 3
					cfg.CircuitBreaker.FailureThreshold = threshold
					var attempts atomic.Int64
					send := func() error {
						attempts.Add(1)
						return fmt.Errorf("delivery failed")
					}
					out := NewOutput(&testutil.MockBatchDriver{
						MockDriver: testutil.MockDriver{
							DriverName: "retry-admission",
							SendFunc: func(context.Context, *event.Event) error {
								return send()
							},
						},
						SendBatchFunc: func(_ context.Context, events []*event.Event) error {
							assert.Len(t, events, batchSize)
							return send()
						},
					}, cfg, nil)
					out.Start(context.Background())
					for range batchSize {
						out.Enqueue(newTestEvent())
					}
					require.NoError(t, out.Retire(context.Background()))
					assert.Equal(t, int64(threshold), attempts.Load())
					status := out.GetStatus()
					assert.Equal(t, batchSize, status.FailedTotal, "events are counted once, not once per attempt")
					assert.Zero(t, status.SentTotal)
					assert.Equal(t, circuitStateOpenName, status.CircuitState)
					assert.Equal(t, "delivery failed", status.LastError)
				})
			})
		}
	}
}

func TestWorkerOldCompletionCannotReleaseHalfOpenProbe(t *testing.T) {
	for _, oldFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("old_fails_%t", oldFails), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := defaultRuntimeDefaults()
				cfg.Workers = 2
				cfg.CircuitBreaker.FailureThreshold = 1
				oldStarted, oldRelease := make(chan struct{}), make(chan struct{})
				probeStarted, probeRelease := make(chan struct{}), make(chan struct{})
				var unexpected atomic.Int64
				out := NewOutput(&testutil.MockDriver{
					DriverName: "generation",
					SendFunc: func(_ context.Context, evt *event.Event) error {
						switch evt.Rule {
						case "old":
							close(oldStarted)
							<-oldRelease
							if oldFails {
								return fmt.Errorf("old request failed")
							}
							return nil
						case "trip":
							return fmt.Errorf("trip circuit")
						case "probe":
							close(probeStarted)
							<-probeRelease
							return nil
						default:
							unexpected.Add(1)
							return nil
						}
					},
				}, cfg, nil)
				enqueue := func(rule string) {
					evt := newTestEvent()
					evt.Rule = rule
					out.Enqueue(evt)
				}
				out.Start(context.Background())
				enqueue("old")
				<-oldStarted
				enqueue("trip")
				synctest.Wait()
				assert.Equal(t, CircuitOpen, out.circuitBreaker.GetState())
				time.Sleep(cfg.CircuitBreaker.ResetTimeout)
				enqueue("probe")
				<-probeStarted
				close(oldRelease)
				synctest.Wait()
				enqueue("blocked")
				synctest.Wait()
				assert.Zero(t, unexpected.Load())
				assert.Equal(t, CircuitHalfOpen, out.circuitBreaker.GetState())
				close(probeRelease)
				require.NoError(t, out.Retire(context.Background()))
				status := out.GetStatus()
				if oldFails {
					assert.Equal(t, 1, status.SentTotal)
					assert.Equal(t, 3, status.FailedTotal)
				} else {
					assert.Equal(t, 2, status.SentTotal)
					assert.Equal(t, 2, status.FailedTotal)
				}
				assert.Empty(t, status.LastError)
				assert.Equal(t, circuitStateHalfOpenName, status.CircuitState)
			})
		})
	}
}

func TestWorkerRetryCanProbeAfterResetTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := defaultRuntimeDefaults()
		cfg.CircuitBreaker.FailureThreshold = 1
		cfg.CircuitBreaker.SuccessThreshold = 1
		cfg.CircuitBreaker.ResetTimeout = time.Second
		cfg.Retry.MaxAttempts = 2
		cfg.Retry.InitialInterval = time.Second
		cfg.Retry.MaxInterval = time.Second
		var attempts atomic.Int64
		out := NewOutput(&testutil.MockDriver{
			DriverName: "reset-retry",
			SendFunc: func(context.Context, *event.Event) error {
				if attempts.Add(1) == 1 {
					return fmt.Errorf("temporary failure")
				}
				return nil
			},
		}, cfg, nil)
		out.Start(context.Background())
		out.Enqueue(newTestEvent())
		require.NoError(t, out.Retire(context.Background()))
		assert.Equal(t, int64(2), attempts.Load())
		status := out.GetStatus()
		assert.Equal(t, 1, status.SentTotal)
		assert.Zero(t, status.FailedTotal)
		assert.Empty(t, status.LastError)
		assert.Equal(t, circuitStateClosedName, status.CircuitState)
	})
}
