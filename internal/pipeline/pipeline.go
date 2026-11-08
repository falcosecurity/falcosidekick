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

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// Pipeline orchestrates event processing: enrich and dispatch.
// The caller owns the worker runtime context and passes it via Start.
// Shutdown delegates to the dispatcher for bounded, orderly teardown.
type Pipeline struct {
	enricher    *Enricher
	dispatcher  *Dispatcher
	metrics     core.MetricsCollector
	stopWorkers context.CancelFunc
}

// NewPipeline creates a Pipeline from its dependencies.
func NewPipeline(
	enricher *Enricher,
	dispatcher *Dispatcher,
	metrics core.MetricsCollector,
) (*Pipeline, error) {
	if enricher == nil {
		return nil, fmt.Errorf("pipeline: enricher is required")
	}
	if dispatcher == nil {
		return nil, fmt.Errorf("pipeline: dispatcher is required")
	}

	return &Pipeline{
		enricher:   enricher,
		dispatcher: dispatcher,
		metrics:    metrics,
	}, nil
}

// Start launches the dispatcher worker pools with the caller-owned worker
// runtime context. stopWorkers is stored and called by Shutdown if the
// drain deadline expires.
func (p *Pipeline) Start(workerRunCtx context.Context, stopWorkers context.CancelFunc) {
	p.stopWorkers = stopWorkers
	p.dispatcher.Start(workerRunCtx)
}

// Shutdown performs orderly teardown bounded by the caller's deadline.
func (p *Pipeline) Shutdown(ctx context.Context) error {
	return p.dispatcher.Shutdown(ctx, p.stopWorkers)
}

// ProcessEvent enriches and dispatches an event to all active outputs.
func (p *Pipeline) ProcessEvent(ctx context.Context, evt *event.Event) {
	if err := p.enricher.Enrich(evt); err != nil {
		if p.metrics != nil {
			p.metrics.RecordError(ctx, "enricher", err)
		}
		return
	}

	if p.metrics != nil {
		p.metrics.RecordEvent(ctx, evt.Rule, evt.Priority, evt.Source)
	}

	p.dispatcher.DispatchEvent(evt)
}

// CollectOutputStatus returns a snapshot of every output's status.
func (p *Pipeline) CollectOutputStatus() []OutputStatus {
	return p.dispatcher.CollectStatus()
}

// GetReadableStore resolves the named output's ReadableStore implementation
// at request time. Returns false if the output is missing or not readable.
func (p *Pipeline) GetReadableStore(name string) (output.ReadableStore, bool) {
	return p.dispatcher.GetReadableStore(name)
}

// Dispatcher returns the underlying dispatcher.
func (p *Pipeline) Dispatcher() *Dispatcher {
	return p.dispatcher
}
