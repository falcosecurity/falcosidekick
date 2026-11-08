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
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestDeriveStatusToken(t *testing.T) {
	tests := []struct {
		name      string
		circuit   string
		lastError string
		want      string
		sentTotal int
	}{
		{name: "idle", circuit: "closed", want: "idle"},
		{name: "ok", circuit: "closed", sentTotal: 3, want: "ok"},
		{name: "open before success", circuit: "open", want: "degraded"},
		{name: "open after success", circuit: "open", sentTotal: 3, want: "degraded"},
		{name: "half-open before success", circuit: "half-open", want: "degraded"},
		{name: "half-open after success", circuit: "half-open", sentTotal: 3, want: "degraded"},
		{name: "error overrides idle", circuit: "closed", lastError: "send failed", want: "error"},
		{name: "error overrides ok", circuit: "closed", lastError: "send failed", sentTotal: 3, want: "error"},
		{name: "error overrides open", circuit: "open", lastError: "send failed", sentTotal: 3, want: "error"},
		{name: "error overrides half-open", circuit: "half-open", lastError: "send failed", sentTotal: 3, want: "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, deriveStatusToken(tt.circuit, tt.lastError, tt.sentTotal))
		})
	}
}

func TestRateWindow(t *testing.T) {
	type step struct {
		second int64
		count  int64
		want   float64
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{
			name: "empty",
			steps: []step{
				{second: 120, want: 0},
				{second: 720, want: 0},
			},
		},
		{
			name: "batch accumulation and expiry",
			steps: []step{
				{second: 120, count: 3, want: 3},
				{second: 120, count: 5, want: 8},
				{second: 179, want: 8},
				{second: 180, want: 0},
			},
		},
		{
			name: "successive buckets across ring boundary",
			steps: []step{
				{second: 119, count: 2, want: 2},
				{second: 120, count: 3, want: 5},
				{second: 178, count: 4, want: 9},
				{second: 179, want: 7},
				{second: 180, want: 4},
				{second: 238, want: 0},
			},
		},
		{
			name: "read advances window before bucket reuse",
			steps: []step{
				{second: 120, count: 3, want: 3},
				{second: 180, want: 0},
				{second: 180, count: 2, want: 2},
				{second: 239, want: 2},
				{second: 240, want: 0},
			},
		},
		{
			name: "long gap before read",
			steps: []step{
				{second: 120, count: 3, want: 3},
				{second: 720, want: 0},
			},
		},
		{
			name: "long gap before record",
			steps: []step{
				{second: 120, count: 3, want: 3},
				{second: 751, count: 2, want: 2},
				{second: 810, want: 2},
				{second: 811, want: 0},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var window rateWindow
			for _, step := range tt.steps {
				if step.count != 0 {
					window.record(step.count, step.second)
				}
				assert.Equal(t, step.want, window.rate(step.second), "second %d", step.second)
			}
		})
	}
}

func TestOutputEventsPerMinuteDelivery(t *testing.T) {
	tests := []struct {
		err       error
		name      string
		batchSize int
	}{
		{name: "single success", batchSize: 1},
		{name: "single failure", batchSize: 1, err: errors.New("send failed")},
		{name: "batch success", batchSize: 3},
		{name: "batch failure", batchSize: 3, err: errors.New("send failed")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := defaultRuntimeDefaults()
				cfg.Batching = &output.BatchingConfig{
					Enabled:       tt.batchSize > 1,
					BatchSize:     tt.batchSize,
					FlushInterval: time.Minute,
				}
				var singleCalls, batchCalls int
				out := NewOutput(&testutil.MockBatchDriver{
					MockDriver: testutil.MockDriver{
						DriverName: "status",
						SendFunc: func(context.Context, *event.Event) error {
							singleCalls++
							return tt.err
						},
					},
					SendBatchFunc: func(_ context.Context, events []*event.Event) error {
						batchCalls++
						assert.Len(t, events, tt.batchSize)
						return tt.err
					},
				}, cfg, nil)
				assert.Zero(t, out.GetStatus().EventsPerMinute)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				out.Start(ctx)
				for range tt.batchSize {
					out.Enqueue(newTestEvent())
				}
				out.closeQueue()
				out.waitDone()
				require.NoError(t, out.Close())

				if tt.batchSize == 1 {
					assert.Equal(t, 1, singleCalls)
					assert.Zero(t, batchCalls)
				} else {
					assert.Zero(t, singleCalls)
					assert.Equal(t, 1, batchCalls)
				}
				status := out.GetStatus()
				var wantRate float64
				if tt.err != nil {
					assert.Zero(t, status.SentTotal)
					assert.Equal(t, tt.batchSize, status.FailedTotal)
					assert.Equal(t, "error", status.Status)
				} else {
					assert.Equal(t, tt.batchSize, status.SentTotal)
					assert.Zero(t, status.FailedTotal)
					assert.Equal(t, "ok", status.Status)
					wantRate = float64(tt.batchSize)
				}
				assert.Equal(t, wantRate, status.EventsPerMinute)
				time.Sleep(59 * time.Second)
				assert.Equal(t, wantRate, out.GetStatus().EventsPerMinute)
				time.Sleep(time.Second)
				assert.Zero(t, out.GetStatus().EventsPerMinute)
			})
		})
	}
}

func TestRateWindowConcurrentReadersAndWriters(t *testing.T) {
	const (
		writers    = 8
		readers    = 4
		iterations = 100
		batchSize  = 3
		second     = 120
		total      = writers * iterations * batchSize
	)
	var window rateWindow
	var callers sync.WaitGroup
	start := make(chan struct{})
	for range writers {
		callers.Go(func() {
			<-start
			for range iterations {
				window.record(batchSize, second)
			}
		})
	}
	for range readers {
		callers.Go(func() {
			<-start
			var previous float64
			for range iterations {
				current := window.rate(second)
				assert.GreaterOrEqual(t, current, previous)
				assert.LessOrEqual(t, current, float64(total))
				previous = current
			}
		})
	}
	close(start)
	callers.Wait()
	assert.Equal(t, float64(total), window.rate(second))
	assert.Zero(t, window.rate(second+60))
}
