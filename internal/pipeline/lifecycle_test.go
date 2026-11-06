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
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

// slowOutput delivers each event after delay and counts the deliveries.
func slowOutput(name string, delay time.Duration, delivered *atomic.Int64) *Output {
	return NewOutput(&testutil.MockDriver{
		DriverName: name,
		SendFunc: func(ctx context.Context, _ *event.Event) error {
			select {
			case <-time.After(delay):
				delivered.Add(1)
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}, defaultRuntimeDefaults(), nil)
}

// Every replacement is live before any predecessor drains: an event dispatched while a slow
// drain holds the reload reaches the new outputs, and a predecessor never gets one after its swap.
func TestApplySwapsEveryOutputBeforeRetiring(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const retireTimeout = 10 * time.Second
		var oldSent, newSent atomic.Int64
		// Every predecessor has a slow delivery in flight, so whichever retires first holds the others.
		running := []*Output{slowOutput("a", time.Minute, &oldSent), slowOutput("b", time.Minute, &oldSent)}
		replacements := map[string]*Output{"a": slowOutput("a", 0, &newSent), "b": slowOutput("b", 0, &newSent)}
		d := NewDispatcher(running)
		d.Start(context.Background())
		for _, out := range running {
			out.Enqueue(newTestEvent())
		}
		synctest.Wait()

		retireCtx, cancel := context.WithTimeout(context.Background(), retireTimeout)
		defer cancel()
		applied := make(chan error)
		go func() { applied <- d.Apply(retireCtx, context.Background(), replacements, nil) }()
		synctest.Wait()
		d.DispatchEvent(newTestEvent())
		synctest.Wait()
		assert.Equal(t, int64(2), newSent.Load(), "both replacements take the event while the slow drain runs")

		start := time.Now()
		require.Error(t, <-applied, "the slow drain misses the deadline")
		assert.Equal(t, retireTimeout, time.Since(start), "every predecessor shares one deadline")
		assert.Zero(t, oldSent.Load())
		require.NoError(t, d.Shutdown(context.Background(), nil))
	})
}

// A predecessor whose retirement missed the deadline is still awaited by Shutdown and absorbed when it ends.
func TestTimedOutRetirementIsAwaitedAndAbsorbed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var closed atomic.Bool
		old := NewOutput(&testutil.MockDriver{
			DriverName: "webhook",
			SendFunc: func(context.Context, *event.Event) error {
				<-release
				return errors.New("late failure")
			},
			CloseFunc: func() error { closed.Store(true); return nil },
		}, defaultRuntimeDefaults(), nil)
		d := NewDispatcher([]*Output{old})
		runCtx, stopWorkers := context.WithCancel(context.Background())
		defer stopWorkers()
		d.Start(runCtx)
		old.Enqueue(newTestEvent())
		synctest.Wait()

		var sent atomic.Int64
		successor := slowOutput("webhook", 0, &sent)
		retireCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		require.Error(t, d.Apply(retireCtx, runCtx, map[string]*Output{"webhook": successor}, nil))
		assert.False(t, closed.Load(), "the driver is not closed during Send")

		shutdown := make(chan error)
		go func() { shutdown <- d.Shutdown(context.Background(), nil) }()
		synctest.Wait()
		select {
		case <-shutdown:
			t.Fatal("Shutdown returned while a predecessor was still retiring")
		default:
		}
		close(release)
		require.NoError(t, <-shutdown)
		assert.True(t, closed.Load())
		synctest.Wait()
		assert.Nil(t, successor.predecessor.Load(), "the late predecessor is absorbed")
		assert.Equal(t, 1, successor.GetStatus().FailedTotal, "its late outcome stays counted")
	})
}

func TestRetireBoundsDriverClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hang := make(chan struct{})
		defer close(hang)
		out := NewOutput(&testutil.MockDriver{
			DriverName: "hanging-close",
			CloseFunc:  func() error { <-hang; return nil },
		}, defaultRuntimeDefaults(), nil)
		out.Start(context.Background())
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		start := time.Now()
		require.Error(t, out.Retire(ctx))
		assert.Equal(t, time.Second, time.Since(start))
	})
}

func TestReplaceCarriesTheLastOutcome(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := NewOutput(&testutil.MockDriver{
			DriverName: "webhook",
			SendFunc:   func(context.Context, *event.Event) error { return errors.New("destination down") },
		}, defaultRuntimeDefaults(), nil)
		d := NewDispatcher([]*Output{old})
		d.Start(context.Background())
		old.Enqueue(newTestEvent())
		synctest.Wait()

		var sent atomic.Int64
		successor := slowOutput("webhook", 0, &sent)
		require.NoError(t, d.ReplaceOutput(context.Background(), context.Background(), "webhook", successor))
		status := successor.GetStatus()
		assert.Equal(t, "destination down", status.LastError, "the replacement shows the outcome it inherits")
		assert.Equal(t, HealthError, status.Status)
		assert.Equal(t, 1, status.FailedTotal)

		successor.Enqueue(newTestEvent())
		synctest.Wait()
		status = successor.GetStatus()
		assert.Empty(t, status.LastError, "its own success replaces the inherited outcome")
		assert.Equal(t, HealthOK, status.Status)
		require.NoError(t, d.Shutdown(context.Background(), nil))
	})
}
