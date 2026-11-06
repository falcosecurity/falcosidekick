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
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

const namespace = "falcosidekick"

// Collector implements core.MetricsCollector using Prometheus client_golang.
type Collector struct {
	reg           *prometheus.Registry
	inputTotal    *prometheus.CounterVec
	outputTotal   *prometheus.CounterVec
	outputLatency *prometheus.HistogramVec
	dropTotal     *prometheus.CounterVec
	errorTotal    *prometheus.CounterVec
	eventTotal    *prometheus.CounterVec
	overflowTotal *prometheus.CounterVec
	// labels bounds the values taken from events: rule, source and the extra labels.
	labels *labelGuard
	// eventLabels name eventTotal's labels: rule, priority, source, then one per extra field.
	eventLabels []string
	// extraFields are the output fields behind the extra labels, in order.
	extraFields []string
}

// NewCollector creates a Collector with its own registry; cfg must be validated.
func NewCollector(cfg core.MetricsConfig) *Collector {
	reg := prometheus.NewRegistry()
	eventLabels := make([]string, 0, 3+len(cfg.ExtraLabels))
	eventLabels = append(eventLabels, "rule", "priority", "source")
	for _, field := range cfg.ExtraLabels {
		eventLabels = append(eventLabels, core.MetricLabelName(field))
	}
	overflowTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "metric_label_overflow_total",
		Help:      "Label values recorded as \"other\" because the label reached metrics.max_label_values.",
	}, []string{"label"})
	c := &Collector{
		reg:           reg,
		extraFields:   cfg.ExtraLabels,
		eventLabels:   eventLabels,
		overflowTotal: overflowTotal,
		labels:        newLabelGuard(cfg.MaxLabelValues, overflowTotal),
		inputTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "input_total",
			Help:      "Total events received by source and status.",
		}, []string{"source", "status"}),
		outputTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "output_total",
			Help:      "Total events per output and delivery outcome; a batch counts each event.",
		}, []string{"output", "status"}),
		outputLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "output_duration_seconds",
			Help:      "Output send latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"output"}),
		dropTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "output_drop_total",
			Help:      "Total events dropped per output (queue full).",
		}, []string{"output"}),
		errorTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "error_total",
			Help:      "Total errors per component.",
		}, []string{"component"}),
		eventTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "event_total",
			Help:      "Total events by rule, priority, source and configured output fields.",
		}, eventLabels),
	}

	reg.MustRegister(
		c.inputTotal,
		c.outputTotal,
		c.outputLatency,
		c.dropTotal,
		c.errorTotal,
		c.eventTotal,
		c.overflowTotal,
	)

	return c
}

// Registry returns the Prometheus registry for HTTP handler setup.
func (c *Collector) Registry() *prometheus.Registry {
	return c.reg
}

// RecordInput increments the input counter; source comes from the event and is bounded.
func (c *Collector) RecordInput(_ context.Context, source, status string) {
	c.inputTotal.WithLabelValues(c.labels.value("source", source), status).Inc()
}

// RecordOutput adds events to the output counter and observes the latency of the request.
func (c *Collector) RecordOutput(_ context.Context, output, status string, events int64, duration time.Duration) {
	c.outputTotal.WithLabelValues(output, status).Add(float64(events))
	if duration > 0 {
		c.outputLatency.WithLabelValues(output).Observe(duration.Seconds())
	}
}

// RecordDrop adds events to the drop counter for the given output.
func (c *Collector) RecordDrop(_ context.Context, output string, events int64) {
	c.dropTotal.WithLabelValues(output).Add(float64(events))
}

// RecordError increments the error counter for the given component.
func (c *Collector) RecordError(_ context.Context, component string, _ error) {
	c.errorTotal.WithLabelValues(component).Inc()
}

// RecordEvent increments the event counter; every label but the validated priority is bounded.
func (c *Collector) RecordEvent(_ context.Context, evt *event.Event) {
	values := make([]string, 0, len(c.eventLabels))
	values = append(values, c.labels.value("rule", evt.Rule), string(evt.Priority), c.labels.value("source", evt.Source))
	for i, field := range c.extraFields {
		value := ""
		if v, ok := evt.OutputFields[field]; ok && v != nil {
			value = fmt.Sprint(v)
		}
		values = append(values, c.labels.value(c.eventLabels[3+i], value))
	}
	c.eventTotal.WithLabelValues(values...).Inc()
}
