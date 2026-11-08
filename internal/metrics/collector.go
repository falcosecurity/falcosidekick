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
	"time"

	"github.com/prometheus/client_golang/prometheus"

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
}

// NewCollector creates a Collector with its own Prometheus registry.
func NewCollector() *Collector {
	reg := prometheus.NewRegistry()
	c := &Collector{
		reg: reg,
		inputTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "input_total",
			Help:      "Total events received by source and status.",
		}, []string{"source", "status"}),
		outputTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "output_total",
			Help:      "Total events sent per output and status.",
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
			Help:      "Total events by rule, priority, and source.",
		}, []string{"rule", "priority", "source"}),
	}

	reg.MustRegister(
		c.inputTotal,
		c.outputTotal,
		c.outputLatency,
		c.dropTotal,
		c.errorTotal,
		c.eventTotal,
	)

	return c
}

// Registry returns the Prometheus registry for HTTP handler setup.
func (c *Collector) Registry() *prometheus.Registry {
	return c.reg
}

// RecordInput increments the input counter.
func (c *Collector) RecordInput(_ context.Context, source, status string) {
	c.inputTotal.WithLabelValues(source, status).Inc()
}

// RecordOutput increments the output counter and observes latency.
func (c *Collector) RecordOutput(_ context.Context, output, status string, duration time.Duration) {
	c.outputTotal.WithLabelValues(output, status).Inc()
	if duration > 0 {
		c.outputLatency.WithLabelValues(output).Observe(duration.Seconds())
	}
}

// RecordDrop increments the drop counter for the given output.
func (c *Collector) RecordDrop(_ context.Context, output string) {
	c.dropTotal.WithLabelValues(output).Inc()
}

// RecordError increments the error counter for the given component.
func (c *Collector) RecordError(_ context.Context, component string, _ error) {
	c.errorTotal.WithLabelValues(component).Inc()
}

// RecordEvent increments the event counter.
func (c *Collector) RecordEvent(_ context.Context, rule string, priority event.Priority, source string) {
	c.eventTotal.WithLabelValues(rule, string(priority), source).Inc()
}
