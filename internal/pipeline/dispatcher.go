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

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// ErrDispatcherStopped is returned when a lifecycle mutation is attempted
// after Shutdown has started. The caller must close any orphaned resources.
var ErrDispatcherStopped = errors.New("dispatcher: stopped")

// Dispatcher manages outputs and routes events with priority filtering.
// Thread-safe for concurrent dispatch and hot-reload lifecycle operations.
type Dispatcher struct {
	outputs  map[string]*Output
	mu       sync.RWMutex
	stopping bool
}

// NewDispatcher creates a Dispatcher for the given outputs.
func NewDispatcher(outputs []*Output) *Dispatcher {
	m := make(map[string]*Output, len(outputs))
	for _, o := range outputs {
		m[o.Name()] = o
	}
	return &Dispatcher{outputs: m}
}

// Start launches all output worker pools with the given context.
func (d *Dispatcher) Start(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, out := range d.outputs {
		out.Start(ctx)
	}
}

// DispatchEvent sends an event to all outputs that accept its priority.
// Returns immediately without enqueuing if the dispatcher is stopping.
func (d *Dispatcher) DispatchEvent(evt *event.Event) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.stopping {
		return
	}
	for _, out := range d.outputs {
		if acceptsPriority(out.config.MinPriority, evt.Priority) {
			out.Enqueue(evt)
		}
	}
}

// Shutdown drains all outputs bounded by ctx, then closes their drivers.
// On deadline, stopWorkers is invoked to force-cancel worker contexts and
// driver close is deferred until workers actually exit; if drivers ignore
// cancellation, that cleanup completes asynchronously.
func (d *Dispatcher) Shutdown(ctx context.Context, stopWorkers context.CancelFunc) error {
	d.mu.Lock()
	if d.stopping {
		d.mu.Unlock()
		return nil
	}
	d.stopping = true
	snapshot := make([]*Output, 0, len(d.outputs))
	for _, out := range d.outputs {
		snapshot = append(snapshot, out)
		out.closeQueue()
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		for _, out := range snapshot {
			out.waitDone()
		}
		close(done)
	}()

	select {
	case <-done:
		for _, out := range snapshot {
			_ = out.Close()
		}
		return nil
	case <-ctx.Done():
	}

	if stopWorkers != nil {
		stopWorkers()
	}

	go func() {
		<-done
		for _, out := range snapshot {
			_ = out.Close()
		}
	}()
	return ctx.Err()
}

// AddOutput starts a new output and adds it to the dispatcher.
// Returns ErrDispatcherStopped if shutdown has started. The caller must
// close any orphaned output on error.
func (d *Dispatcher) AddOutput(runCtx context.Context, out *Output) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopping {
		return ErrDispatcherStopped
	}
	out.Start(runCtx)
	d.outputs[out.Name()] = out
	return nil
}

// RemoveOutput retires the named output using the given deadline context.
// Returns ErrDispatcherStopped if shutdown has started.
func (d *Dispatcher) RemoveOutput(retireCtx context.Context, name string) error {
	d.mu.Lock()
	if d.stopping {
		d.mu.Unlock()
		return ErrDispatcherStopped
	}
	out, exists := d.outputs[name]
	if !exists {
		d.mu.Unlock()
		return nil
	}
	delete(d.outputs, name)
	d.mu.Unlock()

	return out.Retire(retireCtx)
}

// ReplaceOutput atomically swaps an output: the new output starts receiving
// events immediately with runCtx while the old output retires using retireCtx.
// Returns ErrDispatcherStopped if shutdown has started. The caller must
// close any orphaned output on error.
func (d *Dispatcher) ReplaceOutput(retireCtx, runCtx context.Context, name string, newOut *Output) error {
	d.mu.Lock()
	if d.stopping {
		d.mu.Unlock()
		return ErrDispatcherStopped
	}
	old, exists := d.outputs[name]
	newOut.Start(runCtx)
	d.outputs[name] = newOut
	d.mu.Unlock()

	if exists {
		return old.Retire(retireCtx)
	}
	return nil
}

// GetReadableStore looks up the named output and returns its ReadableStore
// implementation. Returns false if the output does not exist or does not
// implement ReadableStore.
func (d *Dispatcher) GetReadableStore(name string) (output.ReadableStore, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out, ok := d.outputs[name]
	if !ok {
		return nil, false
	}
	rs, ok := out.Driver().(output.ReadableStore)
	return rs, ok
}

// CollectStatus returns status for every output.
func (d *Dispatcher) CollectStatus() []OutputStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	statuses := make([]OutputStatus, 0, len(d.outputs))
	for _, out := range d.outputs {
		statuses = append(statuses, out.GetStatus())
	}
	return statuses
}

// OutputNames returns the names of all currently registered outputs.
func (d *Dispatcher) OutputNames() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	names := make([]string, 0, len(d.outputs))
	for name := range d.outputs {
		names = append(names, name)
	}
	return names
}

func acceptsPriority(minPriority, eventPriority event.Priority) bool {
	if minPriority == "" {
		return true
	}
	return eventPriority.GTE(minPriority)
}
