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
	"hash/fnv"

	"go.opentelemetry.io/otel/attribute"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

// tracesSignal has no span processor, so the SDK never exports in the background.
type tracesSignal struct {
	exporter sdktrace.SpanExporter
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
	cfg      *tracesConfig
}

func newTracesSignal(exporter sdktrace.SpanExporter, res *sdkresource.Resource, cfg *tracesConfig) *tracesSignal {
	// Every output field becomes an attribute, none dropped or cut. The literal skips NewSpanLimits,
	// which reads OTEL_* variables.
	limits := sdktrace.SpanLimits{
		AttributeValueLengthLimit:   -1,
		AttributeValueDepthLimit:    sdktrace.DefaultAttributeValueDepthLimit,
		AttributeCountLimit:         -1,
		EventCountLimit:             sdktrace.DefaultEventCountLimit,
		LinkCountLimit:              sdktrace.DefaultLinkCountLimit,
		AttributePerEventCountLimit: sdktrace.DefaultAttributePerEventCountLimit,
		AttributePerLinkCountLimit:  sdktrace.DefaultAttributePerLinkCountLimit,
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithRawSpanLimits(limits),
	)
	tracer := provider.Tracer(scopeName,
		trace.WithInstrumentationVersion(version.Version),
		trace.WithSchemaURL(semconv.SchemaURL),
	)
	return &tracesSignal{exporter: exporter, provider: provider, tracer: tracer, cfg: cfg}
}

func (s *tracesSignal) export(ctx context.Context, events []*event.Event) error {
	spans := make([]sdktrace.ReadOnlySpan, len(events))
	for i, evt := range events {
		spans[i] = s.span(evt)
	}
	return s.exporter.ExportSpans(ctx, spans)
}

func (s *tracesSignal) span(evt *event.Event) sdktrace.ReadOnlySpan {
	parent := context.Background()
	if id, ok := traceID(evt); ok {
		parent = trace.ContextWithSpanContext(parent, trace.NewSpanContext(trace.SpanContextConfig{TraceID: id}))
	}
	_, span := s.tracer.Start(parent, evt.Rule,
		trace.WithTimestamp(evt.Time),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(append(eventAttributes(evt), attribute.String(attrOutput, evt.Output))...),
	)
	span.End(trace.WithTimestamp(evt.Time.Add(s.cfg.Duration)))
	return span.(sdktrace.ReadOnlySpan)
}

// traceID groups events by pod, else container, else host; without any the SDK picks a random ID.
func traceID(evt *event.Event) (trace.TraceID, bool) {
	field := func(name string) string {
		s, _ := evt.OutputFields[name].(string)
		return s
	}
	var key string
	switch ns, pod, container := field("k8s.ns.name"), field("k8s.pod.name"), field("container.id"); {
	case ns != "" && pod != "":
		key = ns + ":" + pod
	case container != "" && container != "host":
		key = container
	case field("evt.hostname") != "":
		key = field("evt.hostname")
	case evt.Hostname != "":
		key = evt.Hostname
	default:
		return trace.TraceID{}, false
	}
	hash := fnv.New128a()
	_, _ = hash.Write([]byte(key))
	var id trace.TraceID
	copy(id[:], hash.Sum(nil))
	return id, true
}

func (s *tracesSignal) shutdown(ctx context.Context) error {
	return errors.Join(s.provider.Shutdown(ctx), s.exporter.Shutdown(ctx))
}
