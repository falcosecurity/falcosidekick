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
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryDelay(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 1, want: 5 * time.Second},
		{failures: 2, want: 10 * time.Second},
		{failures: 3, want: 20 * time.Second},
		{failures: 4, want: 30 * time.Second},
		{failures: 5, want: 30 * time.Second},
		{failures: 1000, want: 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			assert.Equal(t, tt.want, retryDelay(tt.failures, 0.5), "no jitter at the midpoint")
			low, high := retryDelay(tt.failures, 0), retryDelay(tt.failures, 0.999999)
			assert.Equal(t, time.Duration(float64(tt.want)*0.9), low, "-10%")
			assert.Less(t, high, time.Duration(float64(tt.want)*1.1), "under +10%")
			assert.Greater(t, high, time.Duration(float64(tt.want)*1.099), "up to +10%")
		})
	}
}

func TestRetryDelayJitterStaysInBounds(t *testing.T) {
	c := NewCoordinator(nil, slog.Default())
	for range 1000 {
		d := retryDelay(1, c.jitter())
		require.GreaterOrEqual(t, d, 4500*time.Millisecond)
		require.Less(t, d, 5500*time.Millisecond)
	}
}

// fakeReconcile records its triggers and returns the scripted outcomes, then Applied.
type fakeReconcile struct {
	start    time.Time
	release  chan struct{}
	triggers []Trigger
	times    []time.Duration
	outcomes []Outcome
	mu       sync.Mutex
}

func (f *fakeReconcile) reconcile(_ context.Context, trigger Trigger) (Outcome, error) {
	f.mu.Lock()
	f.triggers = append(f.triggers, trigger)
	f.times = append(f.times, time.Since(f.start))
	outcome := OutcomeApplied
	if len(f.outcomes) > 0 {
		outcome, f.outcomes = f.outcomes[0], f.outcomes[1:]
	}
	release := f.release
	f.mu.Unlock()
	if release != nil {
		<-release
	}
	if outcome == OutcomeRejected || outcome == OutcomeRetry {
		return outcome, errors.New("scripted failure")
	}
	return outcome, nil
}

func (f *fakeReconcile) seen() ([]Trigger, []time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Trigger(nil), f.triggers...), append([]time.Duration(nil), f.times...)
}

// startCoordinator runs a coordinator with no jitter; stop waits for Run to return.
func startCoordinator(t *testing.T, f *fakeReconcile) (c *Coordinator, logs *bytes.Buffer, stop func()) {
	t.Helper()
	logs = &bytes.Buffer{}
	c = NewCoordinator(f.reconcile, slog.New(slog.NewTextHandler(logs, nil)))
	c.jitter = func() float64 { return 0.5 }
	f.start = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx)
	}()
	return c, logs, func() {
		cancel()
		<-done
	}
}

func TestCoordinatorCoalescesNotifications(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeReconcile{}
		c := NewCoordinator(f.reconcile, slog.Default())
		c.Notify()
		c.Notify()
		c.Notify()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go c.Run(ctx)
		synctest.Wait()
		triggers, _ := f.seen()
		assert.Equal(t, []Trigger{TriggerChange}, triggers, "notifications before an attempt coalesce")
	})
}

func TestCoordinatorChangeDuringAnAttemptRunsNext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeReconcile{release: make(chan struct{})}
		c, _, stop := startCoordinator(t, f)
		defer stop()

		c.Notify()
		synctest.Wait()
		c.Notify()
		c.Notify()
		f.release <- struct{}{}
		synctest.Wait()
		f.release <- struct{}{}
		synctest.Wait()
		triggers, _ := f.seen()
		assert.Equal(t, []Trigger{TriggerChange, TriggerChange}, triggers, "a change during an attempt gets one more attempt")
	})
}

func TestCoordinatorRetriesTransientFailuresOnATimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeReconcile{outcomes: []Outcome{OutcomeRetry, OutcomeRetry, OutcomeRetry, OutcomeRetry, OutcomeRetry}}
		c, logs, stop := startCoordinator(t, f)
		defer stop()

		c.Notify()
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		triggers, times := f.seen()
		assert.Equal(t, []Trigger{TriggerChange, TriggerRetry, TriggerRetry, TriggerRetry, TriggerRetry, TriggerRetry}, triggers,
			"retried until applied, then no more attempts")
		assert.Equal(t, []time.Duration{0, 5 * time.Second, 15 * time.Second, 35 * time.Second, 65 * time.Second, 95 * time.Second}, times,
			"5s doubling to 30s")
		assert.Contains(t, logs.String(), `msg="reload failed: database unavailable; previous configuration remains active; retry in 5s"`)
		assert.Contains(t, logs.String(), "retry in 30s")
		assert.Contains(t, logs.String(), `reason="scripted failure"`, "the cause is logged with the retry")
	})
}

func TestCoordinatorAppliedResetsTheBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeReconcile{outcomes: []Outcome{OutcomeRetry, OutcomeRetry, OutcomeApplied, OutcomeRetry}}
		c, _, stop := startCoordinator(t, f)
		defer stop()

		c.Notify()
		time.Sleep(time.Minute)
		synctest.Wait()
		c.Notify()
		time.Sleep(6 * time.Second)
		synctest.Wait()
		_, times := f.seen()
		assert.Equal(t, []time.Duration{0, 5 * time.Second, 15 * time.Second, time.Minute, time.Minute + 5*time.Second}, times,
			"the first failure after an apply waits 5s again")
	})
}

func TestCoordinatorSkippedChangeKeepsThePendingRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeReconcile{outcomes: []Outcome{OutcomeRetry, OutcomeSkipped}}
		c, _, stop := startCoordinator(t, f)
		defer stop()

		c.Notify()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		c.Notify()
		time.Sleep(time.Minute)
		synctest.Wait()
		triggers, times := f.seen()
		require.Equal(t, []Trigger{TriggerChange, TriggerChange, TriggerRetry}, triggers)
		assert.Equal(t, 5*time.Second, times[2], "the retry keeps its time")
	})
}

func TestCoordinatorRejectedWaitsForAChangeOrForce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeReconcile{outcomes: []Outcome{OutcomeRetry, OutcomeRejected}}
		c, logs, stop := startCoordinator(t, f)
		defer stop()

		c.Notify()
		synctest.Wait()
		c.Notify()
		time.Sleep(time.Hour)
		synctest.Wait()
		triggers, _ := f.seen()
		assert.Equal(t, []Trigger{TriggerChange, TriggerChange}, triggers, "a rejection cancels the pending retry and waits")
		assert.Contains(t, logs.String(), `msg="reload rejected: invalid configuration; previous configuration remains active"`)
		assert.Equal(t, 1, strings.Count(logs.String(), "reload rejected"))

		c.Force()
		synctest.Wait()
		triggers, _ = f.seen()
		assert.Equal(t, []Trigger{TriggerChange, TriggerChange, TriggerForce}, triggers, "SIGHUP forces an attempt")
	})
}

func TestCoordinatorForceDuringAnAttemptIsKept(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeReconcile{release: make(chan struct{})}
		c, _, stop := startCoordinator(t, f)
		defer stop()

		c.Notify()
		synctest.Wait()
		c.Force()
		c.Notify()
		f.release <- struct{}{}
		synctest.Wait()
		f.release <- struct{}{}
		synctest.Wait()
		triggers, _ := f.seen()
		assert.Equal(t, []Trigger{TriggerChange, TriggerForce}, triggers)
	})
}

// synctest fails the test if Run or its timer goroutine outlives the bubble.
func TestCoordinatorStopsWithTheContextDuringARetryDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeReconcile{outcomes: []Outcome{OutcomeRetry}}
		c, _, stop := startCoordinator(t, f)

		c.Notify()
		time.Sleep(time.Second)
		synctest.Wait()
		before := time.Now()
		stop()
		assert.Equal(t, before, time.Now(), "Run returns at once, not when the retry timer fires")
		time.Sleep(time.Minute)
		synctest.Wait()
		triggers, _ := f.seen()
		assert.Equal(t, []Trigger{TriggerChange}, triggers, "no attempt after the context ends")
	})
}
