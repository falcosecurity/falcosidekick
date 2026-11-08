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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func buildTestPipeline(t *testing.T, outputs []*Output) *Pipeline {
	t.Helper()
	enricher, err := NewEnricher(output.EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	require.NoError(t, err)
	dispatcher := NewDispatcher(outputs)

	p, err := NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)
	return p
}

func TestProcessEventEnrichesAndDispatches(t *testing.T) {
	var received atomic.Int64

	cfg := defaultRuntimeDefaults()
	cfg.MinPriority = event.PriorityDebug
	out := NewOutput(&testutil.MockDriver{
		DriverName: "test",
		SendFunc: func(_ context.Context, _ *event.Event) error {
			received.Add(1)
			return nil
		},
	}, cfg, nil)

	enricher, _ := NewEnricher(output.EnricherConfig{
		CustomFields:           map[string]string{"env": "test"},
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := NewDispatcher([]*Output{out})

	p, err := NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)

	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	p.Start(workerRunCtx, stopWorkers)

	evt := newTestEvent()
	p.ProcessEvent(t.Context(), evt)

	drainCtx, drainCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer drainCancel()
	err = p.Shutdown(drainCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(1), received.Load())
	assert.NotEmpty(t, evt.UUID)
	assert.Equal(t, "test", evt.OutputFields["env"])
}

func TestProcessEventRoutesByPriority(t *testing.T) {
	var slackCalls, lokiCalls atomic.Int64

	slackCfg := defaultRuntimeDefaults()
	slackCfg.MinPriority = event.PriorityCritical
	slackOut := NewOutput(&testutil.MockDriver{DriverName: "slack", SendFunc: func(_ context.Context, _ *event.Event) error {
		slackCalls.Add(1)
		return nil
	}}, slackCfg, nil)

	lokiCfg := defaultRuntimeDefaults()
	lokiCfg.MinPriority = event.PriorityDebug
	lokiOut := NewOutput(&testutil.MockDriver{DriverName: "loki", SendFunc: func(_ context.Context, _ *event.Event) error {
		lokiCalls.Add(1)
		return nil
	}}, lokiCfg, nil)

	enricher, _ := NewEnricher(output.EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	dispatcher := NewDispatcher([]*Output{slackOut, lokiOut})

	p, err := NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)

	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	p.Start(workerRunCtx, stopWorkers)

	evt := newTestEvent()
	evt.Priority = event.PriorityWarning
	p.ProcessEvent(t.Context(), evt)

	drainCtx, drainCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer drainCancel()
	err = p.Shutdown(drainCtx)
	require.NoError(t, err)

	assert.Equal(t, int64(0), slackCalls.Load(), "warning should not reach critical-only slack")
	assert.Equal(t, int64(1), lokiCalls.Load(), "warning should reach debug-level loki")
}

func TestNewPipelineRejectsNilDependencies(t *testing.T) {
	enricher, _ := NewEnricher(output.EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	dispatcher := NewDispatcher(nil)

	tests := []struct {
		enricher   *Enricher
		dispatcher *Dispatcher
		name       string
	}{
		{name: "nil enricher", enricher: nil, dispatcher: dispatcher},
		{name: "nil dispatcher", enricher: enricher, dispatcher: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPipeline(tt.enricher, tt.dispatcher, nil)
			require.Error(t, err)
		})
	}
}

func TestProcessEventWithNoOutputsDoesNotPanic(t *testing.T) {
	enricher, err := NewEnricher(output.EnricherConfig{TruncateEventThreshold: 4096, TruncateFieldThreshold: 512})
	require.NoError(t, err)
	p, err := NewPipeline(enricher, NewDispatcher(nil), nil)
	require.NoError(t, err)

	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	p.Start(workerRunCtx, stopWorkers)

	p.ProcessEvent(t.Context(), newTestEvent())

	drainCtx, drainCancel := context.WithTimeout(t.Context(), 1*time.Second)
	defer drainCancel()
	err = p.Shutdown(drainCtx)
	require.NoError(t, err)
}

func TestCollectOutputStatus(t *testing.T) {
	p := buildTestPipeline(t, []*Output{
		NewOutput(&testutil.MockDriver{DriverName: "slack"}, defaultRuntimeDefaults(), nil),
		NewOutput(&testutil.MockDriver{DriverName: "loki"}, defaultRuntimeDefaults(), nil),
	})

	statuses := p.CollectOutputStatus()
	assert.Len(t, statuses, 2)
}

func TestShutdownCompletesWhenEmpty(t *testing.T) {
	p := buildTestPipeline(t, nil)

	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	p.Start(workerRunCtx, stopWorkers)

	drainCtx, drainCancel := context.WithTimeout(t.Context(), 1*time.Second)
	defer drainCancel()
	err := p.Shutdown(drainCtx)
	require.NoError(t, err)
}

func TestPipelineShutdownBoundedWithStuckSender(t *testing.T) {
	out := NewOutput(&testutil.MockDriver{
		DriverName: "stuck",
		SendFunc: func(ctx context.Context, _ *event.Event) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}, defaultRuntimeDefaults(), nil)

	p := buildTestPipeline(t, []*Output{out})

	workerRunCtx, stopWorkers := context.WithCancel(context.Background())
	p.Start(workerRunCtx, stopWorkers)

	p.ProcessEvent(t.Context(), newTestEvent())
	time.Sleep(20 * time.Millisecond)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer shutdownCancel()

	start := time.Now()
	err := p.Shutdown(shutdownCtx)
	elapsed := time.Since(start)

	assert.Error(t, err, "Shutdown must return error when deadline exceeded with stuck sender")
	assert.Less(t, elapsed, 1*time.Second, "Shutdown must complete within deadline, not hang forever")
}
