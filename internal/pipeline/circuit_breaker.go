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
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	// CircuitClosed allows requests through normally.
	CircuitClosed CircuitState = iota
	// CircuitOpen blocks all requests.
	CircuitOpen
	// CircuitHalfOpen allows exactly one probe request to test recovery.
	CircuitHalfOpen
)

const (
	circuitStateClosedName   = "closed"
	circuitStateOpenName     = "open"
	circuitStateHalfOpenName = "half-open"
	circuitStateUnknownName  = "unknown"
)

// String returns the state name.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return circuitStateClosedName
	case CircuitOpen:
		return circuitStateOpenName
	case CircuitHalfOpen:
		return circuitStateHalfOpenName
	default:
		return circuitStateUnknownName
	}
}

// CircuitBreaker implements the circuit breaker pattern per output.
type CircuitBreaker struct {
	lastFailure time.Time
	// changed is closed and replaced whenever admission may have changed, waking Wait.
	changed      chan struct{}
	cfg          output.CircuitBreakerConfig
	generation   uint64
	failureCount int
	successCount int
	state        CircuitState
	probing      bool
	mu           sync.Mutex
}

// NewCircuitBreaker creates a CircuitBreaker from the given config.
func NewCircuitBreaker(cfg *output.CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{cfg: *cfg, changed: make(chan struct{})}
}

// Wait blocks until a request could be admitted: the circuit is closed, or half-open with no probe running.
// It returns ctx.Err() if ctx ends first. AllowRequest can still refuse when another caller takes the probe.
func (cb *CircuitBreaker) Wait(ctx context.Context) error {
	for {
		cb.mu.Lock()
		cb.advanceState()
		var reopen time.Duration
		ready := false
		switch cb.state {
		case CircuitClosed:
			ready = true
		case CircuitHalfOpen:
			ready = !cb.probing
		case CircuitOpen:
			reopen = cb.cfg.ResetTimeout - time.Since(cb.lastFailure)
		}
		changed := cb.changed
		cb.mu.Unlock()
		if ready {
			return nil
		}
		if err := waitForChange(ctx, changed, reopen); err != nil {
			return err
		}
	}
}

// waitForChange returns when changed is closed, after reopen if positive, or with ctx.Err() when ctx ends.
func waitForChange(ctx context.Context, changed <-chan struct{}, reopen time.Duration) error {
	var timeout <-chan time.Time
	if reopen > 0 {
		timer := time.NewTimer(reopen)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-changed:
	case <-timeout:
	}
	return nil
}

// notify wakes every Wait; it requires cb.mu held.
func (cb *CircuitBreaker) notify() {
	close(cb.changed)
	cb.changed = make(chan struct{})
}

// GetState returns the current state, moving open to half-open once the reset timeout elapsed.
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.advanceState()
	return cb.state
}

// AllowRequest admits one attempt and returns its completion callback, which the caller must call.
// Only the first completion counts, and results from an older state are ignored.
func (cb *CircuitBreaker) AllowRequest() (complete func(success bool), allowed bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.advanceState()

	switch cb.state {
	case CircuitClosed:
	case CircuitOpen:
		return nil, false
	case CircuitHalfOpen:
		if cb.probing {
			return nil, false
		}
		cb.probing = true
	default:
		return nil, false
	}

	generation := cb.generation
	var once sync.Once
	return func(success bool) {
		once.Do(func() { cb.recordResult(generation, success) })
	}, true
}

func (cb *CircuitBreaker) recordResult(generation uint64, success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if generation != cb.generation {
		return
	}

	cb.probing = false
	defer cb.notify()
	if success {
		cb.failureCount = 0
		if cb.state == CircuitHalfOpen {
			cb.successCount++
			if cb.successCount >= cb.cfg.SuccessThreshold {
				cb.transition(CircuitClosed)
			}
		}
		return
	}

	cb.successCount = 0
	cb.failureCount++
	cb.lastFailure = time.Now()
	if cb.state == CircuitHalfOpen || cb.failureCount >= cb.cfg.FailureThreshold {
		cb.transition(CircuitOpen)
	}
}

func (cb *CircuitBreaker) advanceState() {
	if cb.state == CircuitOpen && time.Since(cb.lastFailure) >= cb.cfg.ResetTimeout {
		cb.transition(CircuitHalfOpen)
	}
}

func (cb *CircuitBreaker) transition(state CircuitState) {
	cb.state = state
	cb.generation++
	cb.failureCount = 0
	cb.successCount = 0
	cb.probing = false
	cb.notify()
}
