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

// Health is the coarse state of an output shown by the API and the UI.
type Health string

// Output health values, ordered from worst to best.
const (
	// HealthError means the last delivery failed.
	HealthError Health = "error"
	// HealthDegraded means delivering with the circuit not closed or a warning set.
	HealthDegraded Health = "degraded"
	// HealthIdle means nothing delivered yet and nothing wrong.
	HealthIdle Health = "idle"
	// HealthOK means the last delivery succeeded.
	HealthOK Health = "ok"
)

// OutputStatus holds observable counters and state for one output.
type OutputStatus struct {
	LastSuccess     time.Time `json:"last_success"`
	Name            string    `json:"name"`
	Status          Health    `json:"status"`
	CircuitState    string    `json:"circuit_state"`
	LastError       string    `json:"last_error"`
	LastWarning     string    `json:"last_warning"`
	QueueDepth      int       `json:"queue_depth"`
	QueueCapacity   int       `json:"queue_capacity"`
	SentTotal       int       `json:"sent_total"`
	DroppedTotal    int       `json:"dropped_total"`
	FailedTotal     int       `json:"failed_total"`
	EventsPerMinute float64   `json:"events_per_minute"`
}

func deriveStatusToken(circuit, lastError, lastWarning string, sentTotal int) Health {
	if lastError != "" {
		return HealthError
	}
	switch circuit {
	case CircuitOpen.String(), CircuitHalfOpen.String():
		return HealthDegraded
	}
	if lastWarning != "" {
		return HealthDegraded
	}
	if sentTotal == 0 {
		return HealthIdle
	}
	return HealthOK
}

// Output is the runtime delivery unit for one output destination.
type Output struct {
	lastError      atomic.Value
	driverWarning  atomic.Value
	healthWarning  atomic.Value
	batchSender    output.BatchSender
	metrics        core.MetricsCollector
	driver         output.Driver
	lastSuccess    atomic.Value
	queue          chan *event.Event
	cancel         context.CancelFunc
	circuitBreaker *CircuitBreaker
	// predecessor is the replaced output while it drains.
	predecessor atomic.Pointer[Output]
	config      output.RuntimeConfig
	rateWindow  rateWindow
	workerDone  sync.WaitGroup
	// outcomeMu guards base* and keeps counters consistent with last error and last success.
	outcomeMu    sync.RWMutex
	baseSent     int64
	baseFailed   int64
	baseDropped  int64
	sentTotal    atomic.Int64
	droppedTotal atomic.Int64
	failedTotal  atomic.Int64
}

// totals requires o.outcomeMu held for reading.
func (o *Output) totals() (sent, failed, dropped int64) {
	sent = o.baseSent + o.sentTotal.Load()
	failed = o.baseFailed + o.failedTotal.Load()
	dropped = o.baseDropped + o.droppedTotal.Load()
	if p := o.predecessor.Load(); p != nil {
		p.outcomeMu.RLock()
		ps, pf, pd := p.totals()
		p.outcomeMu.RUnlock()
		sent, failed, dropped = sent+ps, failed+pf, dropped+pd
	}
	return sent, failed, dropped
}

func (o *Output) inherit(prev *Output) { o.predecessor.Store(prev) }

func (o *Output) absorb() {
	o.outcomeMu.Lock()
	defer o.outcomeMu.Unlock()
	p := o.predecessor.Load()
	if p == nil {
		return
	}
	p.outcomeMu.RLock()
	ps, pf, pd := p.totals()
	p.outcomeMu.RUnlock()
	o.baseSent += ps
	o.baseFailed += pf
	o.baseDropped += pd
	o.predecessor.Store(nil)
}

const rateBuckets = 60

// rateWindow is a ring of per-second sent counts covering the last minute.
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
	o.driverWarning.Store("")
	o.healthWarning.Store("")
	if reporter, ok := driver.(output.WarningReporter); ok {
		reporter.SetWarningHandler(func(warning string) { o.driverWarning.Store(warning) })
	}
	if reporter, ok := driver.(output.LateFailureReporter); ok {
		reporter.SetLateFailureHandler(o.recordLateFailure)
	}
	return o
}

// recordLateFailure counts an event that Send accepted but the destination later rejected.
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

// Start launches the workers under a child context that Retire cancels.
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

// Enqueue adds an event to the output queue, dropping it when the queue is full.
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

// Close releases the driver without draining; Retire drains first.
func (o *Output) Close() error {
	return o.driver.Close()
}

// Retire closes the queue, drains bounded by ctx, then closes the driver.
// On deadline it cancels the workers and closes the driver only after they exit, never during Send.
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

// waitDone blocks until workers exit, then counts events left queued as dropped.
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
	o.outcomeMu.RLock()
	sent64, failed64, dropped64 := o.totals()
	sent, failed, dropped := int(sent64), int(failed64), int(dropped64)
	lastErr := o.lastError.Load().(string)
	lastSuccess := o.lastSuccess.Load().(time.Time)
	o.outcomeMu.RUnlock()
	circuit := o.circuitBreaker.GetState().String()
	warning := o.lastWarning()
	return OutputStatus{
		Name:            o.driver.Name(),
		Status:          deriveStatusToken(circuit, lastErr, warning, sent),
		QueueDepth:      len(o.queue),
		QueueCapacity:   o.config.QueueSize,
		SentTotal:       sent,
		DroppedTotal:    dropped,
		FailedTotal:     failed,
		CircuitState:    circuit,
		LastSuccess:     lastSuccess,
		LastError:       lastErr,
		LastWarning:     warning,
		EventsPerMinute: o.rateWindow.rate(time.Now().Unix()),
	}
}

// SetHealthWarning records a destination problem found before the first successful delivery.
func (o *Output) SetHealthWarning(warning string) {
	o.healthWarning.Store(warning)
}

func (o *Output) lastWarning() string {
	if warning := o.driverWarning.Load().(string); warning != "" {
		return warning
	}
	return o.healthWarning.Load().(string)
}

// executeWithRetry counts cancellation during backoff as a failure.
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
			o.outcomeMu.Lock()
			o.failedTotal.Add(count)
			o.outcomeMu.Unlock()
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
			now := time.Now()
			o.outcomeMu.Lock()
			o.lastSuccess.Store(now)
			o.lastError.Store("")
			o.sentTotal.Add(count)
			o.outcomeMu.Unlock()
			o.healthWarning.Store("")
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
	o.outcomeMu.Lock()
	o.lastError.Store(err.Error())
	o.failedTotal.Add(count)
	o.outcomeMu.Unlock()
	if o.metrics != nil {
		o.metrics.RecordOutput(ctx, o.driver.Name(), "error", 0)
		o.metrics.RecordError(ctx, o.driver.Name(), err)
	}
}
