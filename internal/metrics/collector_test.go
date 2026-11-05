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

package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go" //nolint:importas // standard prometheus model import alias
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

func newTestCollector() *Collector {
	return NewCollector()
}

func collectCounter(t *testing.T, c prometheus.Collector) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 10)
	c.Collect(ch)
	close(ch)
	var total float64
	for m := range ch {
		var dto io_prometheus_client.Metric
		require.NoError(t, m.Write(&dto))
		if dto.Counter != nil {
			total += dto.Counter.GetValue()
		}
	}
	return total
}

func TestRecordInput(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordInput(ctx, "syscall", "ok")
	c.RecordInput(ctx, "syscall", "ok")
	c.RecordInput(ctx, "plugin", "error")

	assert.Equal(t, 3.0, collectCounter(t, c.inputTotal))
}

func TestRecordOutput(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordOutput(ctx, "slack", "ok", 100*time.Millisecond)
	c.RecordOutput(ctx, "slack", "error", 0)

	assert.Equal(t, 2.0, collectCounter(t, c.outputTotal))
}

func TestRecordOutputLatency(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordOutput(ctx, "elasticsearch", "ok", 50*time.Millisecond)
	c.RecordOutput(ctx, "elasticsearch", "ok", 150*time.Millisecond)

	ch := make(chan prometheus.Metric, 10)
	c.outputLatency.Collect(ch)
	close(ch)

	var observations uint64
	for m := range ch {
		var dto io_prometheus_client.Metric
		require.NoError(t, m.Write(&dto))
		if dto.Histogram != nil {
			observations += dto.Histogram.GetSampleCount()
		}
	}
	assert.Equal(t, uint64(2), observations)
}

func TestRecordOutputZeroDurationSkipsHistogram(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordOutput(ctx, "slack", "circuit_open", 0)

	ch := make(chan prometheus.Metric, 10)
	c.outputLatency.Collect(ch)
	close(ch)

	var observations uint64
	for m := range ch {
		var dto io_prometheus_client.Metric
		require.NoError(t, m.Write(&dto))
		if dto.Histogram != nil {
			observations += dto.Histogram.GetSampleCount()
		}
	}
	assert.Equal(t, uint64(0), observations, "zero duration must not record histogram observation")
}

func TestRecordDrop(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordDrop(ctx, "loki")
	c.RecordDrop(ctx, "loki")

	assert.Equal(t, 2.0, collectCounter(t, c.dropTotal))
}

func TestRecordError(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordError(ctx, "eventstore", assert.AnError)
	c.RecordError(ctx, "pipeline", assert.AnError)

	assert.Equal(t, 2.0, collectCounter(t, c.errorTotal))
}

func TestRecordEvent(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordEvent(ctx, &event.Event{Rule: "Write below binary dir", Priority: event.PriorityError, Source: "syscall"})
	c.RecordEvent(ctx, &event.Event{Rule: "Read secret", Priority: event.PriorityWarning, Source: "syscall"})

	assert.Equal(t, 2.0, collectCounter(t, c.eventTotal))
}

func TestRecordEventExtraLabels(t *testing.T) {
	c := NewCollector("k8s.ns.name", "proc.pid")
	ctx := context.Background()

	c.RecordEvent(ctx, &event.Event{Rule: "r", Priority: event.PriorityWarning, Source: "syscall",
		OutputFields: map[string]any{"k8s.ns.name": "prod", "proc.pid": 42}})
	c.RecordEvent(ctx, &event.Event{Rule: "r", Priority: event.PriorityWarning, Source: "syscall"})

	families, err := c.Registry().Gather()
	require.NoError(t, err)
	var series []map[string]string
	for _, family := range families {
		if family.GetName() != "falcosidekick_event_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			series = append(series, labels)
		}
	}
	assert.ElementsMatch(t, []map[string]string{
		{"rule": "r", "priority": string(event.PriorityWarning), "source": "syscall", "k8s_ns_name": "prod", "proc_pid": "42"},
		{"rule": "r", "priority": string(event.PriorityWarning), "source": "syscall", "k8s_ns_name": "", "proc_pid": ""},
	}, series)
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ core.MetricsCollector = (*Collector)(nil)
	var _ core.MetricsCollector = NoopCollector{}
}

func TestNoopCollectorDoesNotPanic(t *testing.T) {
	var noop NoopCollector
	ctx := context.Background()

	noop.RecordInput(ctx, "test", "ok")
	noop.RecordOutput(ctx, "test", "ok", time.Second)
	noop.RecordDrop(ctx, "test")
	noop.RecordError(ctx, "test", assert.AnError)
	noop.RecordEvent(ctx, &event.Event{Rule: "rule", Priority: event.PriorityDebug, Source: "test"})
}
