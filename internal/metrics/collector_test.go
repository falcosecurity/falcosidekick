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
	"strings"
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

// series returns the label sets and values of a metric family.
func series(t *testing.T, c *Collector, family string) map[string]float64 {
	t.Helper()
	families, err := c.Registry().Gather()
	require.NoError(t, err)
	all := map[string]float64{}
	for _, f := range families {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			var labels []string
			for _, l := range m.GetLabel() {
				labels = append(labels, l.GetName()+"="+l.GetValue())
			}
			value := m.GetCounter().GetValue() + m.GetGauge().GetValue() + float64(m.GetHistogram().GetSampleCount())
			all[strings.Join(labels, ",")] = value
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

// The exposed names are a contract dashboards and alerts depend on: each says what it counts,
// counters end in _total, durations in _seconds, and the standard Go, process and build metrics exist.
func TestExposedMetricNames(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()
	c.RecordRequest(ctx, core.IngestAccepted)
	c.RecordEvent(ctx, &event.Event{Rule: "r", Priority: event.PriorityWarning, Source: "syscall"})
	c.RecordOutput(ctx, "slack", "sent", 1)
	c.ObserveRequest(ctx, "slack", time.Millisecond)
	c.RecordDrop(ctx, "slack", 1)
	c.WatchOutputs(func() []OutputState { return []OutputState{{Name: "slack"}} })

	families, err := c.Registry().Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
	}
	for _, want := range []string{
		"falcosidekick_ingest_requests_total",
		"falcosidekick_events_total",
		"falcosidekick_output_events_total",
		"falcosidekick_output_request_duration_seconds",
		"falcosidekick_output_dropped_events_total",
		"falcosidekick_output_queue_length",
		"falcosidekick_output_queue_capacity",
		"falcosidekick_output_status",
		"falcosidekick_output_circuit_state",
		"falcosidekick_build_info",
		"go_goroutines",
		"process_start_time_seconds",
	} {
		assert.True(t, names[want], want)
	}
	for name := range names {
		assert.False(t, strings.HasPrefix(name, "falcosidekick_input") || name == "falcosidekick_error_total", name)
	}
}

func TestRecordRequestCountsInvalidPosts(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()
	c.RecordRequest(ctx, core.IngestAccepted)
	c.RecordRequest(ctx, core.IngestAccepted)
	c.RecordRequest(ctx, core.IngestInvalid)
	assert.Equal(t, map[string]float64{"status=accepted": 2, "status=invalid": 1}, series(t, c, "falcosidekick_ingest_requests_total"))
}

func TestRecordOutput(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordOutput(ctx, "slack", "sent", 1)
	c.RecordOutput(ctx, "slack", "error", 1)
	c.RecordOutput(ctx, "elasticsearch", "sent", 500)

	assert.Equal(t, 502.0, collectCounter(t, c.outputEvents), "a batch counts each of its events")
	assert.Empty(t, series(t, c, "falcosidekick_output_request_duration_seconds"), "counting events observes no request")
}

func TestObserveRequest(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.ObserveRequest(ctx, "slack", 100*time.Millisecond)
	c.ObserveRequest(ctx, "slack", 0)
	c.ObserveRequest(ctx, "elasticsearch", time.Second)

	assert.Equal(t, map[string]float64{"output=slack": 2, "output=elasticsearch": 1},
		series(t, c, "falcosidekick_output_request_duration_seconds"), "one observation per attempt")
}

func TestRecordDrop(t *testing.T) {
	c := newTestCollector()
	ctx := context.Background()

	c.RecordDrop(ctx, "loki", 1)
	c.RecordDrop(ctx, "loki", 3)

	assert.Equal(t, 4.0, collectCounter(t, c.outputDropped))
}

func TestRecordEventExtraLabels(t *testing.T) {
	c := NewCollector(core.MetricsConfig{ExtraLabels: []string{"k8s.ns.name", "proc.pid"}, MaxLabelValues: 1000})
	ctx := context.Background()

	c.RecordEvent(ctx, &event.Event{Rule: "r", Priority: event.PriorityWarning, Source: "syscall",
		OutputFields: map[string]any{"k8s.ns.name": "prod", "proc.pid": 42}})
	c.RecordEvent(ctx, &event.Event{Rule: "r", Priority: event.PriorityWarning, Source: "syscall"})

	assert.Equal(t, map[string]float64{
		"k8s_ns_name=prod,priority=Warning,proc_pid=42,rule=r,source=syscall": 1,
		"k8s_ns_name=,priority=Warning,proc_pid=,rule=r,source=syscall":       1,
	}, series(t, c, "falcosidekick_events_total"), "the priority is spelled as Falco does")
}

// Labels taken from events keep at most max_label_values distinct values each.
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

	assert.Equal(t, 5.0, collectCounter(t, c.events), "no event is lost to the cap")
	assert.Equal(t, map[string]float64{"label=rule": 2, "label=k8s_ns_name": 2}, series(t, c, "falcosidekick_label_overflows_total"))
	for labels := range series(t, c, "falcosidekick_events_total") {
		assert.NotContains(t, labels, "rule=c", "a third rule becomes other")
	}
}

// The output gauges are read at scrape time, one series per status and circuit state, so an alert
// can match output_status{status="error"} == 1.
func TestOutputGaugesFollowTheCurrentState(t *testing.T) {
	c := newTestCollector()
	assert.Empty(t, series(t, c, "falcosidekick_output_queue_length"), "nothing before the pipeline is watched")

	state := OutputState{Name: "loki", Status: "degraded", CircuitState: "open", QueueLength: 7, QueueCapacity: 1000}
	c.WatchOutputs(func() []OutputState { return []OutputState{state} })
	assert.Equal(t, map[string]float64{"output=loki": 7}, series(t, c, "falcosidekick_output_queue_length"))
	assert.Equal(t, map[string]float64{"output=loki": 1000}, series(t, c, "falcosidekick_output_queue_capacity"))
	assert.Equal(t, map[string]float64{
		"output=loki,status=ok": 0, "output=loki,status=idle": 0, "output=loki,status=degraded": 1,
		"output=loki,status=error": 0, "output=loki,status=failed": 0,
	}, series(t, c, "falcosidekick_output_status"))
	assert.Equal(t, map[string]float64{
		"output=loki,state=closed": 0, "output=loki,state=open": 1, "output=loki,state=half-open": 0,
	}, series(t, c, "falcosidekick_output_circuit_state"))

	state.QueueLength, state.CircuitState = 0, "closed"
	assert.Equal(t, map[string]float64{"output=loki": 0}, series(t, c, "falcosidekick_output_queue_length"), "read again at each scrape")
}

func TestBuildInfo(t *testing.T) {
	c := newTestCollector()
	got := series(t, c, "falcosidekick_build_info")
	require.Len(t, got, 1)
	for labels, value := range got {
		assert.Equal(t, 1.0, value)
		assert.Contains(t, labels, "version=")
		assert.Contains(t, labels, "revision=")
	}
}

func TestCollectorImplementsInterface(t *testing.T) {
	var _ core.MetricsCollector = (*Collector)(nil)
	var _ core.MetricsCollector = NoopCollector{}
}

func TestNoopCollectorDoesNotPanic(t *testing.T) {
	var noop NoopCollector
	ctx := context.Background()

	noop.RecordRequest(ctx, core.IngestAccepted)
	noop.RecordOutput(ctx, "test", "sent", 1)
	noop.ObserveRequest(ctx, "test", time.Second)
	noop.RecordDrop(ctx, "test", 1)
	noop.RecordEvent(ctx, &event.Event{Rule: "rule", Priority: event.PriorityDebug, Source: "test"})
}
