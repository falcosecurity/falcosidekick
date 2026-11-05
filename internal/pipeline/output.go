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
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// OutputStatus holds observable counters and state for one output.
//
// Status is a coarse health token derived from LastError and CircuitState:
// "error" when LastError is non-empty, "degraded" when the circuit breaker is
// open or half-open, "idle" when closed and never sent, "ok" otherwise.
// EventsPerMinute is a rolling 60-second success rate.
type OutputStatus struct {
	LastSuccess     time.Time `json:"last_success"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	CircuitState    string    `json:"circuit_state"`
	LastError       string    `json:"last_error"`
	QueueDepth      int       `json:"queue_depth"`
	QueueCapacity   int       `json:"queue_capacity"`
	SentTotal       int       `json:"sent_total"`
	DroppedTotal    int       `json:"dropped_total"`
	FailedTotal     int       `json:"failed_total"`
	EventsPerMinute float64   `json:"events_per_minute"`
}

func deriveStatusToken(circuit, lastError string, sentTotal int) string {
	if lastError != "" {
		return "error"
	}
	switch circuit {
	case CircuitOpen.String(), CircuitHalfOpen.String():
		return "degraded"
	}
	if sentTotal == 0 {
		return "idle"
	}
	return "ok"
}

// Output is the runtime delivery unit for one output destination.
type Output struct {
	lastError      atomic.Value
	batchSender    output.BatchSender
	metrics        core.MetricsCollector
	driver         output.Driver
	lastSuccess    atomic.Value
	queue          chan *event.Event
	cancel         context.CancelFunc
	circuitBreaker *CircuitBreaker
	config         output.RuntimeConfig
	rateWindow     rateWindow
	workerDone     sync.WaitGroup
	sentTotal      atomic.Int64
	droppedTotal   atomic.Int64
	failedTotal    atomic.Int64
}

const rateBuckets = 60

// rateWindow maintains a 60-slot ring of per-second sent-event counters so
// GetStatus can report a rolling events-per-minute rate without relying on
// start time or a separate goroutine.
type rateWindow struct {
	mu      sync.Mutex
	buckets [rateBuckets]int64
	last    int64
}

func (r *rateWindow) record(count, nowSec int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advance(nowSec)
	r.buckets[nowSec%rateBuckets] += count
}

func (r *rateWindow) rate(nowSec int64) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.advance(nowSec)
	var sum int64
	for _, v := range r.buckets {
		sum += v
	}
	return float64(sum)
}

func (r *rateWindow) advance(nowSec int64) {
	if r.last == 0 {
		r.last = nowSec
		return
	}
	delta := nowSec - r.last
	if delta <= 0 {
		return
	}
	if delta >= rateBuckets {
		for i := range r.buckets {
			r.buckets[i] = 0
		}
		r.last = nowSec
		return
	}
	for i := int64(1); i <= delta; i++ {
		r.buckets[(r.last+i)%rateBuckets] = 0
	}
	r.last = nowSec
}

// NewOutput creates a complete Output from a driver and configuration.
func NewOutput(driver output.Driver, cfg *output.RuntimeConfig, metrics core.MetricsCollector) *Output {
	o := &Output{
		driver:         driver,
		config:         *cfg,
		queue:          make(chan *event.Event, cfg.QueueSize),
		circuitBreaker: NewCircuitBreaker(cfg.CircuitBreaker),
		metrics:        metrics,
	}
	if bs, ok := driver.(output.BatchSender); ok && cfg.Batching != nil && cfg.Batching.Enabled {
		o.batchSender = bs
	}
	o.lastSuccess.Store(time.Time{})
	o.lastError.Store("")
	if reporter, ok := driver.(output.LateFailureReporter); ok {
		reporter.SetLateFailureHandler(o.recordLateFailure)
	}
	return o
}

// recordLateFailure counts an event that the driver reported as sent and
// later learned was not delivered.
func (o *Output) recordLateFailure(err error) {
	o.recordFailure(context.Background(), 1, err)
}

// Name returns the output driver name.
func (o *Output) Name() string {
	return o.driver.Name()
}

// Driver returns the underlying driver.
func (o *Output) Driver() output.Driver {
	return o.driver
}

// Start launches the worker goroutines. A child context is derived from ctx
// so that Retire can cancel this output's workers independently.
func (o *Output) Start(ctx context.Context) {
	workerCtx, cancel := context.WithCancel(ctx) //nolint:gosec // cancel is stored in o.cancel and called by Retire
	o.cancel = cancel

	worker := o.runWorker
	if o.batchSender != nil {
		worker = o.runBatchWorker
	}
	for i := 0; i < o.config.Workers; i++ {
		o.workerDone.Add(1)
		go func() {
			defer o.workerDone.Done()
			worker(workerCtx)
		}()
	}
}

// Enqueue adds an event to the output queue. Drops the event if the queue is full.
func (o *Output) Enqueue(evt *event.Event) {
	select {
	case o.queue <- evt:
	default:
		o.recordDrop()
	}
}

func (o *Output) recordDrop() {
	o.droppedTotal.Add(1)
	if o.metrics != nil {
		o.metrics.RecordDrop(context.Background(), o.driver.Name())
	}
}

// Close releases the underlying driver resources without draining.
// Use Retire for a graceful stop that drains the queue first.
func (o *Output) Close() error {
	return o.driver.Close()
}

// Retire closes the queue, drains bounded by ctx, then closes the driver.
// On deadline it cancels the worker context and returns; the driver close
// is deferred until workers actually exit. driver.Close is never invoked
// while a worker may still be in Send. Events left in the queue when workers
// exit count as dropped.
func (o *Output) Retire(ctx context.Context) error {
	if o.cancel != nil {
		defer o.cancel()
	}
	close(o.queue)

	done := make(chan struct{})
	go func() {
		o.waitDone()
		close(done)
	}()

	select {
	case <-done:
		_ = o.driver.Close()
		return nil
	case <-ctx.Done():
	}

	go func() {
		<-done
		_ = o.driver.Close()
	}()
	return fmt.Errorf("output %q: retire deadline exceeded, deferred close scheduled", o.driver.Name())
}

func (o *Output) closeQueue() {
	close(o.queue)
}

// waitDone blocks until workers exit, then counts events they left queued.
func (o *Output) waitDone() {
	o.workerDone.Wait()
	for {
		select {
		case _, ok := <-o.queue:
			if !ok {
				return
			}
			o.recordDrop()
		default:
			return
		}
	}
}

// GetStatus returns a snapshot of this output's counters and state.
func (o *Output) GetStatus() OutputStatus {
	circuit := o.circuitBreaker.GetState().String()
	lastErr := o.lastError.Load().(string)
	return OutputStatus{
		Name:            o.driver.Name(),
		Status:          deriveStatusToken(circuit, lastErr, int(o.sentTotal.Load())),
		QueueDepth:      len(o.queue),
		QueueCapacity:   o.config.QueueSize,
		SentTotal:       int(o.sentTotal.Load()),
		DroppedTotal:    int(o.droppedTotal.Load()),
		FailedTotal:     int(o.failedTotal.Load()),
		CircuitState:    circuit,
		LastSuccess:     o.lastSuccess.Load().(time.Time),
		LastError:       lastErr,
		EventsPerMinute: o.rateWindow.rate(time.Now().Unix()),
	}
}

// executeWithRetry runs fn with circuit breaker and retry. On success it adds
// count to sentTotal; on final failure, including cancellation during backoff,
// it adds count to failedTotal.
func (o *Output) executeWithRetry(ctx context.Context, count int64, sendFunc func(ctx context.Context) error) {
	var lastErr error
	for attempt := 0; attempt < o.config.Retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := o.config.Retry.ComputeBackoff(attempt)
			select {
			case <-ctx.Done():
				o.recordFailure(ctx, count, lastErr)
				return
			case <-time.After(backoff):
			}
		}

		complete, allowed := o.circuitBreaker.AllowRequest()
		if !allowed {
			if lastErr != nil {
				break
			}
			o.failedTotal.Add(count)
			if o.metrics != nil {
				o.metrics.RecordOutput(ctx, o.driver.Name(), "circuit_open", 0)
			}
			return
		}

		start := time.Now()
		err := sendFunc(ctx)
		duration := time.Since(start)
		complete(err == nil)

		if err == nil {
			o.sentTotal.Add(count)
			now := time.Now()
			o.lastSuccess.Store(now)
			o.lastError.Store("")
			o.rateWindow.record(count, now.Unix())
			if o.metrics != nil {
				o.metrics.RecordOutput(ctx, o.driver.Name(), "ok", duration)
			}
			return
		}

		lastErr = err
	}

	o.recordFailure(ctx, count, lastErr)
}

func (o *Output) recordFailure(ctx context.Context, count int64, err error) {
	o.failedTotal.Add(count)
	o.lastError.Store(err.Error())
	if o.metrics != nil {
		o.metrics.RecordOutput(ctx, o.driver.Name(), "error", 0)
		o.metrics.RecordError(ctx, o.driver.Name(), err)
	}
}
