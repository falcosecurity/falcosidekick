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
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

// eventName names the log records as OpenTelemetry events.
const eventName = "falco.alert"

// severities maps Falco priorities as the OpenTelemetry log data model maps
// syslog levels.
var severities = map[event.Priority]otellog.Severity{
	event.PriorityEmergency:     otellog.SeverityFatal,
	event.PriorityAlert:         otellog.SeverityError3,
	event.PriorityCritical:      otellog.SeverityError2,
	event.PriorityError:         otellog.SeverityError,
	event.PriorityWarning:       otellog.SeverityWarn,
	event.PriorityNotice:        otellog.SeverityInfo2,
	event.PriorityInformational: otellog.SeverityInfo,
	event.PriorityDebug:         otellog.SeverityDebug,
}

// logsSignal emits one record per event through an instance-scoped
// provider whose only processor hands the records back to the caller, which
// exports them synchronously.
type logsSignal struct {
	exporter sdklog.Exporter
	provider *sdklog.LoggerProvider
	logger   otellog.Logger
}

type captureKey struct{}

// captureProcessor appends each record to the slice carried by the context.
type captureProcessor struct{}

func (captureProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }

func (captureProcessor) OnEmit(ctx context.Context, r *sdklog.Record) error {
	if records, ok := ctx.Value(captureKey{}).(*[]sdklog.Record); ok {
		*records = append(*records, r.Clone())
	}
	return nil
}

func (captureProcessor) Shutdown(context.Context) error   { return nil }
func (captureProcessor) ForceFlush(context.Context) error { return nil }

func newLogsSignal(exporter sdklog.Exporter, res *sdkresource.Resource) *logsSignal {
	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(captureProcessor{}),
		sdklog.WithAttributeCountLimit(-1),
	)
	logger := provider.Logger(scopeName,
		otellog.WithInstrumentationVersion(version.Version),
		otellog.WithSchemaURL(semconv.SchemaURL),
	)
	return &logsSignal{exporter: exporter, provider: provider, logger: logger}
}

func (s *logsSignal) export(ctx context.Context, events []*event.Event) error {
	records := make([]sdklog.Record, 0, len(events))
	capture := context.WithValue(context.Background(), captureKey{}, &records)
	now := time.Now()
	for _, evt := range events {
		s.logger.Emit(capture, logRecord(evt, now))
	}
	return s.exporter.Export(ctx, records)
}

func logRecord(evt *event.Event, observed time.Time) otellog.Record {
	var r otellog.Record
	r.SetEventName(eventName)
	r.SetTimestamp(evt.Time)
	r.SetObservedTimestamp(observed)
	r.SetSeverity(severities[evt.Priority])
	r.SetSeverityText(evt.Priority.String())
	r.SetBody(attribute.StringValue(evt.Output))
	r.AddAttributes(eventAttributes(evt)...)
	return r
}

func (s *logsSignal) shutdown(ctx context.Context) error {
	return errors.Join(s.provider.Shutdown(ctx), s.exporter.Shutdown(ctx))
}
