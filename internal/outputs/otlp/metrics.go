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

package otlp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

const (
	// counterName becomes falcosecurity_falco_rules_matches_total in Prometheus.
	counterName = "falcosecurity.falco.rules.matches"
	counterUnit = "{match}"
	counterDesc = "Number of Falco rule matches."

	// maxCounted bounds the UUIDs remembered as counted; a retry comes long before this many newer events.
	maxCounted = 100_000
	// seriesLimit is the SDK default, set so OTEL_GO_X_CARDINALITY_LIMIT has no effect; beyond it the
	// SDK adds to one overflow series.
	seriesLimit = 2000
)

// metricsSignal exports a cumulative counter, so the next export repairs a failed one. An event is
// counted once by UUID, however often its batch is retried, also when the retry is for another signal.
type metricsSignal struct {
	exporter sdkmetric.Exporter
	provider *sdkmetric.MeterProvider
	reader   *sdkmetric.ManualReader
	counter  metric.Int64Counter
	counted  map[string]struct{}
	// order holds the counted UUIDs as a ring; next is the oldest once the ring is full.
	order   []string
	extra   []string
	next    int
	countMu sync.Mutex
	// exportMu keeps collections in order: a cumulative point that reaches the collector after a newer
	// one reads as a counter reset.
	exportMu sync.Mutex
}

func newMetricsSignal(exporter sdkmetric.Exporter, res *sdkresource.Resource, cfg *metricsConfig) (*metricsSignal, error) {
	reader := sdkmetric.NewManualReader(
		sdkmetric.WithTemporalitySelector(exporter.Temporality),
		sdkmetric.WithAggregationSelector(exporter.Aggregation),
	)
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
		// Explicit, so OTEL_METRICS_EXEMPLAR_FILTER and OTEL_GO_X_CARDINALITY_LIMIT have no effect.
		sdkmetric.WithExemplarFilter(exemplar.AlwaysOffFilter),
		sdkmetric.WithCardinalityLimit(seriesLimit),
	)
	meter := provider.Meter(scopeName,
		metric.WithInstrumentationVersion(version.Version),
		metric.WithSchemaURL(semconv.SchemaURL),
	)
	counter, err := meter.Int64Counter(counterName, metric.WithUnit(counterUnit), metric.WithDescription(counterDesc))
	if err != nil {
		return nil, fmt.Errorf("counter: %w", err)
	}
	return &metricsSignal{
		exporter: exporter,
		provider: provider,
		reader:   reader,
		counter:  counter,
		counted:  make(map[string]struct{}),
		extra:    cfg.ExtraAttributes,
	}, nil
}

func (s *metricsSignal) export(ctx context.Context, events []*event.Event) error {
	s.count(events)
	s.exportMu.Lock()
	defer s.exportMu.Unlock()
	var rm metricdata.ResourceMetrics
	if err := s.reader.Collect(ctx, &rm); err != nil {
		return err
	}
	return s.exporter.Export(ctx, &rm)
}

// count adds the events not counted yet; an event without a UUID is counted every time.
func (s *metricsSignal) count(events []*event.Event) {
	s.countMu.Lock()
	defer s.countMu.Unlock()
	for _, evt := range events {
		if evt.UUID != "" {
			if _, done := s.counted[evt.UUID]; done {
				continue
			}
			s.remember(evt.UUID)
		}
		s.counter.Add(context.Background(), 1, metric.WithAttributes(s.attributes(evt)...))
	}
}

// remember records uuid as counted, forgetting the oldest once maxCounted are kept.
func (s *metricsSignal) remember(uuid string) {
	if len(s.order) < maxCounted {
		s.order = append(s.order, uuid)
	} else {
		delete(s.counted, s.order[s.next])
		s.order[s.next] = uuid
		s.next = (s.next + 1) % maxCounted
	}
	s.counted[uuid] = struct{}{}
}

func (s *metricsSignal) attributes(evt *event.Event) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 5+len(s.extra))
	attrs = append(attrs,
		attribute.String(attrRule, evt.Rule),
		attribute.String(attrPriority, evt.Priority.String()),
		attribute.String(attrSource, evt.Source),
	)
	attrs = appendIdentity(attrs, evt)
	for _, field := range s.extra {
		if value, ok := evt.OutputFields[field]; ok {
			attrs = append(attrs, fieldAttribute(field, value))
		}
	}
	return attrs
}

func (s *metricsSignal) shutdown(ctx context.Context) error {
	return errors.Join(s.provider.Shutdown(ctx), s.exporter.Shutdown(ctx))
}
