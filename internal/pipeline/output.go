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
	// HealthFailed means the output is not running: its stored configuration did not build.
	HealthFailed Health = "failed"
	// HealthError means the last delivery failed.
	HealthError Health = "error"
	// HealthDegraded means delivering with the circuit not closed or a warning set.
	HealthDegraded Health = "degraded"
	// HealthIdle means nothing delivered yet and nothing wrong.
	HealthIdle Health = "idle"
	// HealthOK means the last delivery succeeded.
	HealthOK Health = "ok"
)

// WarningKind says what LastWarning is about.
type WarningKind string

// Warning kinds; empty without a warning.
const (
	// WarningDestination means the destination failed its probe before start or fails in part.
	WarningDestination WarningKind = "destination"
	// WarningUpdate means a stored change of this output was not applied; the output runs as before.
	WarningUpdate WarningKind = "update"
	// WarningRotation means a renewed secret file was not applied; the output keeps its previous secret.
	WarningRotation WarningKind = "rotation"
)

type warning struct {
	text string
	kind WarningKind
}

// OutputStatus holds observable counters and state for one output.
type OutputStatus struct {
	LastSuccess     time.Time   `json:"last_success"`
	Name            string      `json:"name"`
	Status          Health      `json:"status"`
	CircuitState    string      `json:"circuit_state"`
	LastError       string      `json:"last_error"`
	LastWarning     string      `json:"last_warning"`
	WarningKind     WarningKind `json:"warning_kind"`
	QueueDepth      int         `json:"queue_depth"`
	QueueCapacity   int         `json:"queue_capacity"`
	SentTotal       int         `json:"sent_total"`
	DroppedTotal    int         `json:"dropped_total"`
	FailedTotal     int         `json:"failed_total"`
	EventsPerMinute float64     `json:"events_per_minute"`
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
	// updateWarning names a stored change or secret rotation this output could not be replaced with; a replacement clears it.
	updateWarning atomic.Value
	driverWarning atomic.Value
	// destinationWarning names a failed probe or a batch delivered in part; a clean delivery clears it.
	destinationWarning atomic.Value
	batchSender        output.BatchSender
	metrics            core.MetricsCollector
	driver             output.Driver
	queue              chan *event.Event
	cancel             context.CancelFunc
	circuitBreaker     *CircuitBreaker
	// retired is closed once Retire's workers exited and the driver closed, even past Retire's deadline.
	retired chan struct{}
	// outcome is shared with every output this one replaced, see inherit.
	outcome    atomic.Pointer[outcome]
	config     output.RuntimeConfig
	workerDone sync.WaitGroup
}

// outcome is the delivery record of one output name. A replacement shares its predecessor's record,
// so what the predecessor still delivers, fails or drops while it retires lands in the same record.
type outcome struct {
	lastSuccess time.Time
	lastError   string
	rate        rateWindow
	mu          sync.RWMutex
	sent        int64
	failed      int64
	dropped     int64
}

type outcomeSnapshot struct {
	lastSuccess           time.Time
	lastError             string
	sent, failed, dropped int64
}

func (r *outcome) succeeded(count int64, now time.Time) {
	r.mu.Lock()
	r.lastSuccess, r.lastError = now, ""
	r.sent += count
	r.mu.Unlock()
	r.rate.record(count, now.Unix())
}

func (r *outcome) failedWith(count int64, err error) {
	r.mu.Lock()
	r.lastError = err.Error()
	r.failed += count
	r.mu.Unlock()
}

func (r *outcome) failedN(count int64) {
	r.mu.Lock()
	r.failed += count
	r.mu.Unlock()
}

func (r *outcome) droppedN(count int64) {
	r.mu.Lock()
	r.dropped += count
	r.mu.Unlock()
}

func (r *outcome) snapshot() outcomeSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return outcomeSnapshot{lastSuccess: r.lastSuccess, lastError: r.lastError, sent: r.sent, failed: r.failed, dropped: r.dropped}
}

// inherit makes o continue prev's delivery record; it must run before o starts.
func (o *Output) inherit(prev *Output) {
	o.outcome.Store(prev.outcome.Load())
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
		retired:        make(chan struct{}),
	}
	if bs, ok := driver.(output.BatchSender); ok && cfg.Batching.IsEnabled() {
		o.batchSender = bs
	}
	o.outcome.Store(&outcome{})
	o.updateWarning.Store(warning{})
	o.driverWarning.Store("")
	o.destinationWarning.Store("")
	if reporter, ok := driver.(output.WarningReporter); ok {
		reporter.SetWarningHandler(func(warning string) { o.driverWarning.Store(warning) })
	}
	return o
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
	workerCtx, cancel := context.WithCancel(ctx)
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

func (o *Output) recordDrop() { o.recordDrops(1) }

// recordDrops counts events that leave the output without a delivery attempt.
func (o *Output) recordDrops(count int64) {
	o.outcome.Load().droppedN(count)
	if o.metrics != nil {
		o.metrics.RecordDrop(context.Background(), o.driver.Name(), count)
	}
}

// Close releases the driver without draining; Retire drains first.
func (o *Output) Close() error {
	return o.driver.Close()
}

// Retire closes the queue, drains, then closes the driver, all bounded by ctx; call it once. On deadline it cancels the workers; the
// driver is closed only after they exit, never during Send, and Retired reports when that happened.
func (o *Output) Retire(ctx context.Context) error {
	close(o.queue)
	go func() {
		o.waitDone()
		_ = o.driver.Close()
		close(o.retired)
	}()

	select {
	case <-o.retired:
		o.stopWorkers()
		return nil
	case <-ctx.Done():
		o.stopWorkers()
		return fmt.Errorf("output %q: retire deadline exceeded, deferred close scheduled", o.driver.Name())
	}
}

// Retired is closed once a Retire finished, including the deferred close after its deadline.
func (o *Output) Retired() <-chan struct{} { return o.retired }

func (o *Output) stopWorkers() {
	if o.cancel != nil {
		o.cancel()
	}
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
	record := o.outcome.Load()
	s := record.snapshot()
	circuit := o.circuitBreaker.GetState().String()
	current := o.lastWarning()
	return OutputStatus{
		Name:            o.driver.Name(),
		Status:          deriveStatusToken(circuit, s.lastError, current.text, int(s.sent)),
		QueueDepth:      len(o.queue),
		QueueCapacity:   o.config.QueueSize,
		SentTotal:       int(s.sent),
		DroppedTotal:    int(s.dropped),
		FailedTotal:     int(s.failed),
		CircuitState:    circuit,
		LastSuccess:     s.lastSuccess,
		LastError:       s.lastError,
		LastWarning:     current.text,
		WarningKind:     current.kind,
		EventsPerMinute: record.rate.rate(time.Now().Unix()),
	}
}

// SetHealthWarning records a destination problem found before the first successful delivery.
func (o *Output) SetHealthWarning(warning string) {
	o.destinationWarning.Store(warning)
}

// setUpdateWarning records a change this output was not replaced with; an empty text clears it.
func (o *Output) setUpdateWarning(kind WarningKind, text string) {
	if text == "" {
		kind = ""
	}
	o.updateWarning.Store(warning{text: text, kind: kind})
}

func (o *Output) lastWarning() warning {
	if update := o.updateWarning.Load().(warning); update.text != "" {
		return update
	}
	if text := o.driverWarning.Load().(string); text != "" {
		return warning{text: text, kind: WarningDestination}
	}
	if text := o.destinationWarning.Load().(string); text != "" {
		return warning{text: text, kind: WarningDestination}
	}
	return warning{}
}

// executeWithRetry delivers events through send, retrying with backoff; cancellation during backoff
// fails the undelivered events. A partial batch error accounts its events at once and retries only the retryable ones.
func (o *Output) executeWithRetry(ctx context.Context, events []*event.Event, send func(ctx context.Context, events []*event.Event) error) {
	// Events a stopped worker still holds were never attempted.
	if ctx.Err() != nil {
		o.recordDrops(int64(len(events)))
		return
	}
	var lastErr, rejection error
	for attempt := 0; attempt < o.config.Retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := o.config.Retry.ComputeBackoff(attempt)
			select {
			case <-ctx.Done():
				o.recordFailure(ctx, int64(len(events)), lastErr)
				o.warnRejection(rejection)
				return
			case <-time.After(backoff):
			}
		}

		complete, allowed := o.circuitBreaker.AllowRequest()
		// Before the first attempt the events wait for the circuit; once attempted, a refused retry ends them.
		for !allowed && lastErr == nil {
			if o.circuitBreaker.Wait(ctx) != nil {
				o.recordDrops(int64(len(events)))
				return
			}
			complete, allowed = o.circuitBreaker.AllowRequest()
		}
		if !allowed {
			break
		}

		start := time.Now()
		err := send(ctx, events)
		if o.metrics != nil {
			o.metrics.ObserveRequest(ctx, o.driver.Name(), time.Since(start))
		}
		if err == nil {
			complete(true)
			o.recordSuccess(ctx, int64(len(events)))
			o.warnRejection(rejection)
			return
		}
		lastErr = err

		if rejected, retryable, ok := output.PartialEvents(err, len(events)); ok {
			// The destination answered: only a remainder it may still take counts against the circuit.
			complete(len(retryable) == 0)
			if delivered := len(events) - len(rejected) - len(retryable); delivered > 0 {
				o.recordSuccess(ctx, int64(delivered))
			}
			if len(rejected) > 0 {
				o.recordRejected(ctx, int64(len(rejected)))
				rejection = err
			}
			if len(retryable) == 0 {
				o.warnRejection(rejection)
				return
			}
			events = pick(events, retryable)
			continue
		}

		permanent := output.IsPermanent(err)
		// A permanent rejection proves the destination answers, so it does not count against the circuit.
		complete(permanent)
		if permanent {
			break
		}
	}

	o.recordFailure(ctx, int64(len(events)), lastErr)
	o.warnRejection(rejection)
}

func pick(events []*event.Event, indexes []int) []*event.Event {
	picked := make([]*event.Event, len(indexes))
	for i, index := range indexes {
		picked[i] = events[index]
	}
	return picked
}

func (o *Output) recordSuccess(ctx context.Context, count int64) {
	o.outcome.Load().succeeded(count, time.Now())
	o.destinationWarning.Store("")
	if o.metrics != nil {
		o.metrics.RecordOutput(ctx, o.driver.Name(), "ok", count)
	}
}

func (o *Output) recordFailure(ctx context.Context, count int64, err error) {
	o.outcome.Load().failedWith(count, err)
	if o.metrics != nil {
		o.metrics.RecordOutput(ctx, o.driver.Name(), "error", count)
	}
}

// recordRejected fails count events without touching last_error: the delivery did not fail.
func (o *Output) recordRejected(ctx context.Context, count int64) {
	o.outcome.Load().failedN(count)
	if o.metrics != nil {
		o.metrics.RecordOutput(ctx, o.driver.Name(), "error", count)
	}
}

// warnRejection sets the destination warning after the deliveries of the same call cleared it; nil leaves it.
func (o *Output) warnRejection(err error) {
	if err != nil {
		o.destinationWarning.Store(err.Error())
	}
}
