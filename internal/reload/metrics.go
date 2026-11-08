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

package reload

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "falcosidekick"

// Allowed values for the "source" label on reload_* counters/histogram.
const (
	SourceFile = "file"
	SourceUI   = "ui"
)

type reloadMetrics struct {
	total       *prometheus.CounterVec
	failures    *prometheus.CounterVec
	partial     *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	lastSuccess prometheus.Gauge
}

// newReloadMetrics constructs and optionally registers the reload metrics.
// A nil registerer skips registration.
func newReloadMetrics(reg prometheus.Registerer) *reloadMetrics {
	m := &reloadMetrics{
		total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reload_total",
			Help:      "Total reload attempts including no-op. Label source is file (file-driven) or ui (UI-driven apply).",
		}, []string{"source"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reload_failures_total",
			Help:      "Failed reload attempts by source (file or ui).",
		}, []string{"source"}),
		partial: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reload_partial_total",
			Help:      "Reload attempts where runtime apply succeeded but a non-runtime step failed, by source.",
		}, []string{"source"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "reload_duration_seconds",
			Help:      "Duration of reload cycles in seconds, by source.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"source"}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "reload_last_success_timestamp",
			Help:      "Unix timestamp of last fully successful reload from any source.",
		}),
	}

	if reg != nil {
		reg.MustRegister(m.total, m.failures, m.partial, m.duration, m.lastSuccess)
	}

	return m
}

func (m *reloadMetrics) recordSuccess(d time.Duration, source string) {
	m.total.WithLabelValues(source).Inc()
	m.duration.WithLabelValues(source).Observe(d.Seconds())
	m.lastSuccess.SetToCurrentTime()
}

func (m *reloadMetrics) recordPartialSuccess(d time.Duration, source string) {
	m.total.WithLabelValues(source).Inc()
	m.partial.WithLabelValues(source).Inc()
	m.duration.WithLabelValues(source).Observe(d.Seconds())
}

func (m *reloadMetrics) recordFailure(d time.Duration, source string) {
	m.total.WithLabelValues(source).Inc()
	m.failures.WithLabelValues(source).Inc()
	m.duration.WithLabelValues(source).Observe(d.Seconds())
}

func (m *reloadMetrics) recordNoop(source string) {
	m.total.WithLabelValues(source).Inc()
}
