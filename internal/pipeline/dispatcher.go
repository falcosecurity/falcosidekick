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
	outputs map[string]*Output
	// retiring holds the outputs replaced or removed whose retirement has not finished; Shutdown awaits them.
	retiring map[*Output]struct{}
	mu       sync.RWMutex
	stopping bool
}

// NewDispatcher creates a Dispatcher for the given outputs.
func NewDispatcher(outputs []*Output) *Dispatcher {
	m := make(map[string]*Output, len(outputs))
	for _, o := range outputs {
		m[o.Name()] = o
	}
	return &Dispatcher{outputs: m, retiring: make(map[*Output]struct{})}
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
// It also awaits the outputs still retiring after a reload, which close their own drivers.
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
	retiring := make([]*Output, 0, len(d.retiring))
	for out := range d.retiring {
		retiring = append(retiring, out)
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		for _, out := range snapshot {
			out.waitDone()
		}
		for _, out := range retiring {
			<-out.Retired()
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

// Apply starts the outputs in set on runCtx, replacing the running ones with the same name, and removes
// the names in remove, in one step. Then it retires every predecessor concurrently, bounded by retireCtx,
// and returns the retirements that missed it. A successor shares its predecessor's delivery record, so
// what the predecessor does while it retires, even late, is counted. On ErrDispatcherStopped the caller
// still owns set and must close it.
func (d *Dispatcher) Apply(retireCtx, runCtx context.Context, set map[string]*Output, remove []string) error {
	d.mu.Lock()
	if d.stopping {
		d.mu.Unlock()
		return ErrDispatcherStopped
	}
	var retiring []*Output
	for name, out := range set {
		if old, exists := d.outputs[name]; exists {
			out.inherit(old)
			retiring = append(retiring, old)
		}
		out.Start(runCtx)
		d.outputs[name] = out
	}
	for _, name := range remove {
		if old, exists := d.outputs[name]; exists {
			delete(d.outputs, name)
			retiring = append(retiring, old)
		}
	}
	for _, old := range retiring {
		d.retiring[old] = struct{}{}
	}
	d.mu.Unlock()

	errs := make([]error, len(retiring))
	var wg sync.WaitGroup
	for i, old := range retiring {
		wg.Go(func() { errs[i] = old.Retire(retireCtx) })
		go func() {
			<-old.Retired()
			d.mu.Lock()
			delete(d.retiring, old)
			d.mu.Unlock()
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// AddOutput starts a new output and adds it; on error the caller still owns out and must close it.
func (d *Dispatcher) AddOutput(runCtx context.Context, out *Output) error {
	return d.Apply(runCtx, runCtx, map[string]*Output{out.Name(): out}, nil)
}

// RemoveOutput retires the named output bounded by retireCtx.
func (d *Dispatcher) RemoveOutput(retireCtx context.Context, name string) error {
	return d.Apply(retireCtx, retireCtx, nil, []string{name})
}

// ReplaceOutput swaps in newOut on runCtx while the old output retires on retireCtx.
// On ErrDispatcherStopped the caller still owns newOut and must close it.
func (d *Dispatcher) ReplaceOutput(retireCtx, runCtx context.Context, name string, newOut *Output) error {
	return d.Apply(retireCtx, runCtx, map[string]*Output{name: newOut}, nil)
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
