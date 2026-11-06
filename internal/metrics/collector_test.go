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
	return NewCollector(core.MetricsConfig{MaxLabelValues: 1000})
}

// series returns the label sets of a metric family.
func series(t *testing.T, c *Collector, family string) []map[string]string {
	t.Helper()
	families, err := c.Registry().Gather()
	require.NoError(t, err)
	var all []map[string]string
	for _, f := range families {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			all = append(all, labels)
		}
	}
	return all
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

	c.RecordOutput(ctx, "slack", "ok", 1, 100*time.Millisecond)
	c.RecordOutput(ctx, "slack", "error", 1, 0)
	c.RecordOutput(ctx, "elasticsearch", "ok", 500, time.Second)

	assert.Equal(t, 502.0, collectCounter(t, c.outputTotal), "a batch counts each of its events")
}

func TestRecordOutputLatency(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordOutput(ctx, "elasticsearch", "ok", 10, 50*time.Millisecond)
	c.RecordOutput(ctx, "elasticsearch", "ok", 10, 150*time.Millisecond)

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

	c.RecordOutput(ctx, "slack", "error", 1, 0)

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

	c.RecordDrop(ctx, "loki", 1)
	c.RecordDrop(ctx, "loki", 3)

	assert.Equal(t, 4.0, collectCounter(t, c.dropTotal))
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
	c := NewCollector(core.MetricsConfig{ExtraLabels: []string{"k8s.ns.name", "proc.pid"}, MaxLabelValues: 1000})
	ctx := context.Background()

	c.RecordEvent(ctx, &event.Event{Rule: "r", Priority: event.PriorityWarning, Source: "syscall",
		OutputFields: map[string]any{"k8s.ns.name": "prod", "proc.pid": 42}})
	c.RecordEvent(ctx, &event.Event{Rule: "r", Priority: event.PriorityWarning, Source: "syscall"})

	assert.ElementsMatch(t, []map[string]string{
		{"rule": "r", "priority": string(event.PriorityWarning), "source": "syscall", "k8s_ns_name": "prod", "proc_pid": "42"},
		{"rule": "r", "priority": string(event.PriorityWarning), "source": "syscall", "k8s_ns_name": "", "proc_pid": ""},
	}, series(t, c, "falcosidekick_event_total"))
}

// D8: labels taken from events keep at most max_label_values distinct values each.
func TestEventLabelsAreBounded(t *testing.T) {
	c := NewCollector(core.MetricsConfig{ExtraLabels: []string{"k8s.ns.name"}, MaxLabelValues: 2})
	ctx := context.Background()
	record := func(rule, ns string) {
		c.RecordEvent(ctx, &event.Event{Rule: rule, Priority: event.PriorityWarning, Source: "syscall",
			OutputFields: map[string]any{"k8s.ns.name": ns}})
	}
	record("a", "prod")
	record("b", "prod")
	record("c", "dev")
	record("d", "qa")
	record("a", "qa")

	rules := map[string]bool{}
	namespaces := map[string]bool{}
	for _, s := range series(t, c, "falcosidekick_event_total") {
		rules[s["rule"]] = true
		namespaces[s["k8s_ns_name"]] = true
	}
	assert.Equal(t, map[string]bool{"a": true, "b": true, "other": true}, rules, "a value seen before keeps its series")
	assert.Equal(t, map[string]bool{"prod": true, "dev": true, "other": true}, namespaces)
	assert.Equal(t, 5.0, collectCounter(t, c.eventTotal), "no event is lost to the cap")

	overflow := map[string]float64{}
	families, err := c.Registry().Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() == "falcosidekick_metric_label_overflow_total" {
			for _, m := range f.GetMetric() {
				overflow[m.GetLabel()[0].GetValue()] = m.GetCounter().GetValue()
			}
		}
	}
	assert.Equal(t, map[string]float64{"rule": 2, "k8s_ns_name": 2}, overflow)

	c.RecordInput(ctx, "s1", "accepted")
	c.RecordInput(ctx, "s2", "accepted")
	assert.ElementsMatch(t, []map[string]string{
		{"source": "s1", "status": "accepted"}, {"source": "other", "status": "accepted"},
	}, series(t, c, "falcosidekick_input_total"), "input and event share the source budget: syscall and s1")
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ core.MetricsCollector = (*Collector)(nil)
	var _ core.MetricsCollector = NoopCollector{}
}

func TestNoopCollectorDoesNotPanic(t *testing.T) {
	var noop NoopCollector
	ctx := context.Background()

	noop.RecordInput(ctx, "test", "ok")
	noop.RecordOutput(ctx, "test", "ok", 1, time.Second)
	noop.RecordDrop(ctx, "test", 1)
	noop.RecordError(ctx, "test", assert.AnError)
	noop.RecordEvent(ctx, &event.Event{Rule: "rule", Priority: event.PriorityDebug, Source: "test"})
}
