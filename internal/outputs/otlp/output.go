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
	"net/http"
	"net/url"
	"strings"
	"time"

	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

const (
	name = "otlp"

	signalTraces  = "traces"
	signalLogs    = "logs"
	signalMetrics = "metrics"
)

// retriableCodes are the gRPC codes the OTLP specification lets a client retry.
// https://opentelemetry.io/docs/specs/otlp/#failures
var retriableCodes = map[codes.Code]bool{
	codes.Canceled: true, codes.DeadlineExceeded: true, codes.Aborted: true,
	codes.OutOfRange: true, codes.Unavailable: true, codes.DataLoss: true,
}

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
		return nil, fmt.Errorf("%s config: %w", name, err)
	}
	cfg.applyDefaults()
	if errs := cfg.validate(); len(errs) > 0 {
		return nil, fmt.Errorf("%s: %s", name, errs.Error())
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
			return fmt.Errorf("%s %s: %w", name, signalTraces, err)
		}
		exporter, err := newSpanExporter(ctx, settings)
		if err != nil {
			return fmt.Errorf("%s %s: %w", name, signalTraces, err)
		}
		s := newTracesSignal(exporter, res, c)
		d.signals = append(d.signals, signal{name: signalTraces, export: s.export, shutdown: s.shutdown, timeout: c.Timeout})
	}
	if c := d.cfg.Logs; c != nil {
		settings, err := newExporterSettings(c, "/v1/logs")
		if err != nil {
			return fmt.Errorf("%s %s: %w", name, signalLogs, err)
		}
		exporter, err := newLogExporter(ctx, settings)
		if err != nil {
			return fmt.Errorf("%s %s: %w", name, signalLogs, err)
		}
		s := newLogsSignal(exporter, res)
		d.signals = append(d.signals, signal{name: signalLogs, export: s.export, shutdown: s.shutdown, timeout: c.Timeout})
	}
	if c := d.cfg.Metrics; c != nil {
		settings, err := newExporterSettings(&c.signalConfig, "/v1/metrics")
		if err != nil {
			return fmt.Errorf("%s %s: %w", name, signalMetrics, err)
		}
		exporter, err := newMetricExporter(ctx, settings)
		if err != nil {
			return fmt.Errorf("%s %s: %w", name, signalMetrics, err)
		}
		s, err := newMetricsSignal(exporter, res, c)
		if err != nil {
			_ = exporter.Shutdown(ctx)
			return fmt.Errorf("%s %s: %w", name, signalMetrics, err)
		}
		d.signals = append(d.signals, signal{name: signalMetrics, export: s.export, shutdown: s.shutdown, timeout: c.Timeout})
	}
	return nil
}

func (d *driver) Send(ctx context.Context, evt *event.Event) error {
	return d.SendBatch(ctx, []*event.Event{evt})
}

func (d *driver) SendBatch(ctx context.Context, events []*event.Event) error {
	if len(d.signals) == 0 {
		return fmt.Errorf("%s: %w", name, core.ErrNotReady)
	}
	var failures []*shared.DeliveryError
	for _, s := range d.signals {
		var httpStatus int
		if err := s.export(withStatus(ctx, &httpStatus), events); err != nil {
			failures = append(failures, newDeliveryError(s.name, httpStatus, err))
		}
	}
	switch len(failures) {
	case 0:
		return nil
	case 1:
		return failures[0]
	default:
		return joinFailures(ctx, failures)
	}
}

// newDeliveryError names a gRPC failure by its code, classified per the OTLP specification,
// and an HTTP failure by the recorded status, since the exporter's text carries the response body.
func newDeliveryError(signalName string, httpStatus int, err error) *shared.DeliveryError {
	if st, ok := status.FromError(err); ok && st.Code() != codes.Canceled && st.Code() != codes.DeadlineExceeded {
		return &shared.DeliveryError{
			Cause: err, Output: name, Operation: signalName, Code: st.Code().String(), Permanent: !retriableCodes[st.Code()],
		}
	}
	// The HTTP client returns *url.Error when no response settles the request, such as a refused redirect.
	if _, transport := errors.AsType[*url.Error](err); !transport && httpStatus >= http.StatusMultipleChoices {
		return &shared.DeliveryError{Cause: err, Output: name, Operation: signalName, Status: httpStatus}
	}
	return shared.NewDeliveryError(name, signalName, err)
}

// joinFailures reports several failed signals; the batch is permanent only when every signal failed for good.
func joinFailures(ctx context.Context, failures []*shared.DeliveryError) *shared.DeliveryError {
	reasons := make([]string, len(failures))
	permanent := true
	for i, failure := range failures {
		reasons[i] = failure.Operation + ": " + failure.Reason()
		permanent = permanent && output.IsPermanent(failure)
	}
	return &shared.DeliveryError{
		Cause: ctx.Err(), Output: name, Operation: shared.OpSend, Code: strings.Join(reasons, "; "), Permanent: permanent,
	}
}

// HealthCheck is a no-op: OTLP has no request that exports nothing.
func (d *driver) HealthCheck(context.Context) error { return nil }

// Close needs no flush: exports are synchronous.
func (d *driver) Close() error {
	errs := make([]error, 0, len(d.signals))
	for _, s := range d.signals {
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		errs = append(errs, s.shutdown(ctx))
		cancel()
	}
	d.signals = nil
	return shared.WrapDeliveryError(name, shared.OpClose, errors.Join(errs...))
}
