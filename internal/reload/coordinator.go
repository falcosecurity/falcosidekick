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
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

// Retry delays after a transient failure: retryBase doubling up to retryMax, each within ±retryJitter.
const (
	retryBase   = 5 * time.Second
	retryMax    = 30 * time.Second
	retryJitter = 0.1
)

// ReconcileFunc makes one attempt to apply the current input.
type ReconcileFunc func(ctx context.Context, trigger Trigger) (Outcome, error)

// Coordinator runs every file reconcile on one goroutine; Notify and Force only wake it, so calls
// coalesce into the next attempt. A transient failure is retried on a timer.
type Coordinator struct {
	reconcile ReconcileFunc
	logger    *slog.Logger
	// jitter returns a value in [0, 1).
	jitter func() float64
	wake   chan struct{}
	force  atomic.Bool
}

// NewCoordinator returns a coordinator that calls reconcile from Run.
func NewCoordinator(reconcile ReconcileFunc, logger *slog.Logger) *Coordinator {
	return &Coordinator{
		reconcile: reconcile,
		logger:    logger,
		jitter:    rand.Float64,
		wake:      make(chan struct{}, 1),
	}
}

// Notify asks for an attempt on a change the watcher or the poller saw. It never blocks.
func (c *Coordinator) Notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Force asks for an attempt that ignores what was applied or rejected before, as SIGHUP does.
func (c *Coordinator) Force() {
	c.force.Store(true)
	c.Notify()
}

// Run makes the attempts until ctx is canceled; the retry timer stops with it.
func (c *Coordinator) Run(ctx context.Context) {
	var retry *time.Timer
	var retryC <-chan time.Time
	failures := 0
	stopRetry := func() {
		if retry != nil {
			retry.Stop()
		}
		retry, retryC, failures = nil, nil, 0
	}
	defer stopRetry()

	for {
		trigger := TriggerChange
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
			if c.force.Swap(false) {
				trigger = TriggerForce
			}
		case <-retryC:
			retry, retryC = nil, nil
			trigger = TriggerRetry
		}
		if ctx.Err() != nil {
			return
		}

		outcome, err := c.reconcile(ctx, trigger)
		switch outcome {
		case OutcomeSkipped:
			// A skipped change leaves a pending retry in place.
			if retry == nil {
				failures = 0
			}
		case OutcomeApplied, OutcomeStopped:
			stopRetry()
		case OutcomeRejected:
			stopRetry()
			c.logger.Error("reload rejected: invalid configuration; previous configuration remains active", "reason", err)
		case OutcomeRetry:
			failures++
			delay := retryDelay(failures, c.jitter())
			if retry != nil {
				retry.Stop()
			}
			retry = time.NewTimer(delay)
			retryC = retry.C
			c.logger.Error(fmt.Sprintf("reload failed: database unavailable; previous configuration remains active; retry in %s",
				delay.Round(time.Second)), "reason", err)
		}
	}
}

// retryDelay returns the delay before retry number failures, failures >= 1, for jitter in [0, 1).
func retryDelay(failures int, jitter float64) time.Duration {
	base := retryBase
	for i := 1; i < failures && base < retryMax; i++ {
		base *= 2
	}
	base = min(base, retryMax)
	return time.Duration(float64(base) * (1 - retryJitter + 2*retryJitter*jitter))
}
