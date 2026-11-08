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
	// SourceReplica counts the reconciles that apply changes other instances stored in a shared database.
	SourceReplica = "replica"
)

// Values of the "result" label of reloads_total.
const (
	resultSuccess = "success"
	resultPartial = "partial"
	resultFailure = "failure"
	resultNoop    = "noop"
)

type reloadMetrics struct {
	total       *prometheus.CounterVec
	duration    *prometheus.HistogramVec
	lastSuccess prometheus.Gauge
}

// newReloadMetrics registers the metrics unless reg is nil.
func newReloadMetrics(reg prometheus.Registerer) *reloadMetrics {
	m := &reloadMetrics{
		total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reloads_total",
			Help: "Reload attempts by source (file, ui, or replica: changes from another instance) and result: " +
				"success, partial (outputs applied, a later step failed), failure, or noop (nothing changed).",
		}, []string{"source", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "reload_duration_seconds",
			Help:      "Duration of reloads that changed something, by source.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"source"}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "reload_last_success_timestamp_seconds",
			Help:      "Unix time of the last fully successful reload from any source.",
		}),
	}

	if reg != nil {
		reg.MustRegister(m.total, m.duration, m.lastSuccess)
	}

	return m
}

func (m *reloadMetrics) recordSuccess(d time.Duration, source string) {
	m.total.WithLabelValues(source, resultSuccess).Inc()
	m.duration.WithLabelValues(source).Observe(d.Seconds())
	m.lastSuccess.SetToCurrentTime()
}

func (m *reloadMetrics) recordPartialSuccess(d time.Duration, source string) {
	m.total.WithLabelValues(source, resultPartial).Inc()
	m.duration.WithLabelValues(source).Observe(d.Seconds())
}

func (m *reloadMetrics) recordFailure(d time.Duration, source string) {
	m.total.WithLabelValues(source, resultFailure).Inc()
	m.duration.WithLabelValues(source).Observe(d.Seconds())
}

func (m *reloadMetrics) recordNoop(source string) {
	m.total.WithLabelValues(source, resultNoop).Inc()
}
