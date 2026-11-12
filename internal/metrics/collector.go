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
	"fmt"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

const namespace = "falcosidekick"

// Collector implements core.MetricsCollector using Prometheus client_golang.
type Collector struct {
	reg             *prometheus.Registry
	ingestRequests  *prometheus.CounterVec
	outputEvents    *prometheus.CounterVec
	outputDuration  *prometheus.HistogramVec
	outputDropped   *prometheus.CounterVec
	events          *prometheus.CounterVec
	labelOverflows  *prometheus.CounterVec
	outputStateFunc atomic.Pointer[func() []OutputState]
	// labels bounds the values taken from events: rule, source and the extra labels.
	labels *labelGuard
	// eventLabels name the events counter's labels: rule, priority, source, then one per extra field.
	eventLabels []string
	// extraFields are the output fields behind the extra labels, in order.
	extraFields []string
}

// NewCollector creates a Collector with its own registry; cfg must be validated. The registry also
// holds the Go runtime, process and build_info metrics.
func NewCollector(cfg core.MetricsConfig) *Collector {
	reg := prometheus.NewRegistry()
	eventLabels := make([]string, 0, 3+len(cfg.ExtraLabels))
	eventLabels = append(eventLabels, "rule", "priority", "source")
	for _, field := range cfg.ExtraLabels {
		eventLabels = append(eventLabels, core.MetricLabelName(field))
	}
	labelOverflows := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "label_overflows_total",
		Help:      "Label values recorded as \"other\" because the label reached metrics.max_label_values.",
	}, []string{"label"})
	c := &Collector{
		reg:            reg,
		extraFields:    cfg.ExtraLabels,
		eventLabels:    eventLabels,
		labelOverflows: labelOverflows,
		labels:         newLabelGuard(cfg.MaxLabelValues, labelOverflows),
		ingestRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "ingest_requests_total",
			Help:      "Requests posted to the ingestion endpoint: accepted, or invalid (not a valid Falco event).",
		}, []string{"status"}),
		events: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "events_total",
			Help:      "Events accepted, by rule, priority, source and the configured output fields.",
		}, eventLabels),
		outputEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "output_events_total",
			Help:      "Events per output and delivery outcome (ok, error); a batch counts each event.",
		}, []string{"output", "status"}),
		outputDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "output_request_duration_seconds",
			Help:      "Duration of each delivery attempt of an output, failed or not, a batch being one request.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"output"}),
		outputDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "output_dropped_events_total",
			Help:      "Events an output dropped because its queue was full.",
		}, []string{"output"}),
	}

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		buildInfo(),
		c.ingestRequests,
		c.events,
		c.outputEvents,
		c.outputDuration,
		c.outputDropped,
		c.labelOverflows,
		outputStateCollector{c},
	)

	return c
}

func buildInfo() prometheus.Collector {
	info := version.GetInfo()
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   namespace,
		Name:        "build_info",
		Help:        "Always 1; the labels name the running build.",
		ConstLabels: prometheus.Labels{"version": info.Version, "revision": info.Commit, "goversion": info.GoVersion},
	})
	gauge.Set(1)
	return gauge
}

// Registry returns the Prometheus registry.
func (c *Collector) Registry() *prometheus.Registry {
	return c.reg
}

// RecordRequest counts a request to the ingestion endpoint by outcome.
func (c *Collector) RecordRequest(_ context.Context, status string) {
	c.ingestRequests.WithLabelValues(status).Inc()
}

// RecordOutput adds events to the output counter.
func (c *Collector) RecordOutput(_ context.Context, output, status string, events int64) {
	c.outputEvents.WithLabelValues(output, status).Add(float64(events))
}

// ObserveRequest observes the duration of one delivery attempt.
func (c *Collector) ObserveRequest(_ context.Context, output string, duration time.Duration) {
	c.outputDuration.WithLabelValues(output).Observe(duration.Seconds())
}

// RecordDrop adds events to the drop counter for the given output.
func (c *Collector) RecordDrop(_ context.Context, output string, events int64) {
	c.outputDropped.WithLabelValues(output).Add(float64(events))
}

// RecordEvent increments the event counter; every label but the validated priority is bounded.
func (c *Collector) RecordEvent(_ context.Context, evt *event.Event) {
	values := make([]string, 0, len(c.eventLabels))
	values = append(values, c.labels.value("rule", evt.Rule), evt.Priority.String(), c.labels.value("source", evt.Source))
	for i, field := range c.extraFields {
		value := ""
		if v, ok := evt.OutputFields[field]; ok && v != nil {
			value = fmt.Sprint(v)
		}
		values = append(values, c.labels.value(c.eventLabels[3+i], value))
	}
	c.events.WithLabelValues(values...).Inc()
}

// OutputState is what the output gauges report for one output at scrape time.
type OutputState struct {
	Name          string
	Status        string
	CircuitState  string
	QueueLength   int
	QueueCapacity int
}

// Output health and circuit values, one series each, so an alert can match the state.
var (
	outputStatuses = []string{"ok", "idle", "degraded", "error", "failed"}
	circuitStates  = []string{"closed", "open", "half-open"}
)

// WatchOutputs makes the output gauges read states at every scrape.
func (c *Collector) WatchOutputs(states func() []OutputState) {
	c.outputStateFunc.Store(&states)
}

var (
	queueLengthDesc = prometheus.NewDesc(namespace+"_output_queue_length",
		"Events waiting in the output's queue.", []string{"output"}, nil)
	queueCapacityDesc = prometheus.NewDesc(namespace+"_output_queue_capacity",
		"Events the output's queue holds before it drops new ones.", []string{"output"}, nil)
	statusDesc = prometheus.NewDesc(namespace+"_output_status",
		"1 for the output's current status, 0 for the others.", []string{"output", "status"}, nil)
	circuitDesc = prometheus.NewDesc(namespace+"_output_circuit_state",
		"1 for the output's current circuit breaker state, 0 for the others.", []string{"output", "state"}, nil)
)

// outputStateCollector reads the output states on each scrape, so the gauges never go stale.
type outputStateCollector struct{ c *Collector }

func (o outputStateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- queueLengthDesc
	ch <- queueCapacityDesc
	ch <- statusDesc
	ch <- circuitDesc
}

func (o outputStateCollector) Collect(ch chan<- prometheus.Metric) {
	states := o.c.outputStateFunc.Load()
	if states == nil {
		return
	}
	for _, s := range (*states)() {
		ch <- prometheus.MustNewConstMetric(queueLengthDesc, prometheus.GaugeValue, float64(s.QueueLength), s.Name)
		ch <- prometheus.MustNewConstMetric(queueCapacityDesc, prometheus.GaugeValue, float64(s.QueueCapacity), s.Name)
		for _, status := range outputStatuses {
			ch <- prometheus.MustNewConstMetric(statusDesc, prometheus.GaugeValue, oneIf(status == s.Status), s.Name, status)
		}
		for _, state := range circuitStates {
			ch <- prometheus.MustNewConstMetric(circuitDesc, prometheus.GaugeValue, oneIf(state == s.CircuitState), s.Name, state)
		}
	}
}

func oneIf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
