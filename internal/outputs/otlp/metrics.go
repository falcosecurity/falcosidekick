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

	maxPendingCounted = 100_000
)

// metricsSignal exports a cumulative counter, so the next export repairs a failed one.
// Events counted but not yet exported are kept by UUID so a retry does not count them twice.
type metricsSignal struct {
	exporter sdkmetric.Exporter
	provider *sdkmetric.MeterProvider
	reader   *sdkmetric.ManualReader
	counter  metric.Int64Counter
	pending  map[string]struct{}
	extra    []string
	mu       sync.Mutex
}

func newMetricsSignal(exporter sdkmetric.Exporter, res *sdkresource.Resource, cfg *metricsConfig) (*metricsSignal, error) {
	reader := sdkmetric.NewManualReader(
		sdkmetric.WithTemporalitySelector(exporter.Temporality),
		sdkmetric.WithAggregationSelector(exporter.Aggregation),
	)
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(reader))
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
		pending:  make(map[string]struct{}),
		extra:    cfg.ExtraAttributes,
	}, nil
}

func (s *metricsSignal) export(ctx context.Context, events []*event.Event) error {
	included := s.count(events)
	var rm metricdata.ResourceMetrics
	if err := s.reader.Collect(ctx, &rm); err != nil {
		return err
	}
	if err := s.exporter.Export(ctx, &rm); err != nil {
		return err
	}
	s.mu.Lock()
	for _, uuid := range included {
		delete(s.pending, uuid)
	}
	s.mu.Unlock()
	return nil
}

// count adds uncounted events and returns the UUIDs the next collection includes.
func (s *metricsSignal) count(events []*event.Event) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, evt := range events {
		if _, counted := s.pending[evt.UUID]; counted {
			continue
		}
		if evt.UUID != "" && len(s.pending) < maxPendingCounted {
			s.pending[evt.UUID] = struct{}{}
		}
		s.counter.Add(context.Background(), 1, metric.WithAttributes(s.attributes(evt)...))
	}
	uuids := make([]string, 0, len(s.pending))
	for uuid := range s.pending {
		uuids = append(uuids, uuid)
	}
	return uuids
}

func (s *metricsSignal) attributes(evt *event.Event) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 5+len(s.extra))
	attrs = append(attrs,
		attribute.String(attrRule, evt.Rule),
		attribute.String(attrPriority, string(evt.Priority)),
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
