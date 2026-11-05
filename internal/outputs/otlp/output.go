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
	"time"

	sdkresource "go.opentelemetry.io/otel/sdk/resource"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const name = "otlp"

// OutputType describes the OTLP output for the catalog.
var OutputType = output.Type{
	New:      createOutput,
	Name:     name,
	Category: "observability",
	Schema:   output.Schema{Fields: schemaFields()},
}

type exportFunc func(ctx context.Context, events []*event.Event) error

// signal is one enabled OTLP signal with its own exporter.
type signal struct {
	export   exportFunc
	shutdown func(ctx context.Context) error
	name     string
	timeout  time.Duration
}

type driver struct {
	signals []signal
	cfg     config
}

func createOutput(raw map[string]any, _ output.Deps) (output.Driver, error) {
	var cfg config
	if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
		return nil, fmt.Errorf("otlp config: %w", err)
	}
	cfg.applyDefaults()
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("otlp: %s", errs.Error())
	}
	return &driver{cfg: cfg}, nil
}

func (d *driver) Name() string { return name }

func (d *driver) RuntimeConfig() output.RuntimeConfig { return d.cfg.Runtime }

// Init creates one exporter per enabled signal; gRPC connections open on first use.
func (d *driver) Init(ctx context.Context) error {
	if err := d.init(ctx, newResource()); err != nil {
		_ = d.Close()
		return err
	}
	return nil
}

func (d *driver) init(ctx context.Context, res *sdkresource.Resource) error {
	if c := d.cfg.Traces; c != nil {
		settings, err := newExporterSettings(&c.signalConfig, "/v1/traces")
		if err != nil {
			return fmt.Errorf("otlp traces: %w", err)
		}
		exporter, err := newSpanExporter(ctx, settings)
		if err != nil {
			return fmt.Errorf("otlp traces: %w", err)
		}
		s := newTracesSignal(exporter, res, c)
		d.signals = append(d.signals, signal{name: "traces", export: s.export, shutdown: s.shutdown, timeout: c.Timeout})
	}
	if c := d.cfg.Logs; c != nil {
		settings, err := newExporterSettings(c, "/v1/logs")
		if err != nil {
			return fmt.Errorf("otlp logs: %w", err)
		}
		exporter, err := newLogExporter(ctx, settings)
		if err != nil {
			return fmt.Errorf("otlp logs: %w", err)
		}
		s := newLogsSignal(exporter, res)
		d.signals = append(d.signals, signal{name: "logs", export: s.export, shutdown: s.shutdown, timeout: c.Timeout})
	}
	if c := d.cfg.Metrics; c != nil {
		settings, err := newExporterSettings(&c.signalConfig, "/v1/metrics")
		if err != nil {
			return fmt.Errorf("otlp metrics: %w", err)
		}
		exporter, err := newMetricExporter(ctx, settings)
		if err != nil {
			return fmt.Errorf("otlp metrics: %w", err)
		}
		s, err := newMetricsSignal(exporter, res, c)
		if err != nil {
			_ = exporter.Shutdown(ctx)
			return fmt.Errorf("otlp metrics: %w", err)
		}
		d.signals = append(d.signals, signal{name: "metrics", export: s.export, shutdown: s.shutdown, timeout: c.Timeout})
	}
	return nil
}

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	return d.SendBatch(ctx, []*event.Event{evt})
}

func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if len(d.signals) == 0 {
		return fmt.Errorf("otlp: %w", core.ErrNotReady)
	}
	var errs []error
	for _, s := range d.signals {
		if err := s.export(ctx, events); err != nil {
			errs = append(errs, fmt.Errorf("otlp %s: %w", s.name, err))
		}
	}
	return errors.Join(errs...)
}

// HealthCheck is a no-op: OTLP has no request that exports nothing.
func (d *driver) HealthCheck(context.Context) error { return nil }

// Close needs no flush: exports are synchronous.
func (d *driver) Close() error {
	var errs []error
	for _, s := range d.signals {
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		if err := s.shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("otlp %s shutdown: %w", s.name, err))
		}
		cancel()
	}
	d.signals = nil
	return errors.Join(errs...)
}
