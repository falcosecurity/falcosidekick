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

// ErrDispatcherStopped is returned by lifecycle mutations after Shutdown has started.
var ErrDispatcherStopped = errors.New("dispatcher: stopped")

// Dispatcher routes events to outputs by priority; it is safe for concurrent dispatch and reload.
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

// Shutdown drains all outputs, then closes their drivers in parallel, both bounded by ctx.
// On deadline it calls stopWorkers and closes drivers in the background once workers exit.
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
		closed := closeAll(snapshot)
		select {
		case <-closed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
	}

	if stopWorkers != nil {
		stopWorkers()
	}

	go func() {
		<-done
		<-closeAll(snapshot)
	}()
	return ctx.Err()
}

func closeAll(outputs []*Output) <-chan struct{} {
	closed := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for _, out := range outputs {
			wg.Go(func() { _ = out.Close() })
		}
		wg.Wait()
		close(closed)
	}()
	return closed
}

// AddOutput starts a new output and adds it; on error the caller still owns out and must close it.
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

// RemoveOutput retires the named output bounded by retireCtx.
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

// ReplaceOutput atomically swaps in newOut on runCtx while the old output retires on retireCtx.
// On ErrDispatcherStopped the caller still owns newOut and must close it.
func (d *Dispatcher) ReplaceOutput(retireCtx, runCtx context.Context, name string, newOut *Output) error {
	d.mu.Lock()
	if d.stopping {
		d.mu.Unlock()
		return ErrDispatcherStopped
	}
	old, exists := d.outputs[name]
	if exists {
		newOut.inherit(old)
	}
	newOut.Start(runCtx)
	d.outputs[name] = newOut
	d.mu.Unlock()

	if !exists {
		return nil
	}
	if err := old.Retire(retireCtx); err != nil {
		return err
	}
	newOut.absorb()
	return nil
}

// GetReadableStore returns the named output's ReadableStore, if it has one.
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
