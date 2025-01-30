// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.23.1"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

const (
	OTLPinstrumentationName    = "falco"
	OTLPinstrumentationVersion = "v0.1.0"
)

func newResource() *otelresource.Resource {
	return otelresource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(OTLPinstrumentationName),
		semconv.ServiceVersion(OTLPinstrumentationVersion),
	)
}

func installTracesExportPipeline(config *types.Configuration, ctx context.Context) (func(context.Context) error, error) {
	var exporter sdktrace.SpanExporter
	var err error
	switch config.OTLP.Traces.Protocol {
	case GRPC:
		opts := []otlptracegrpc.Option{}
		if !config.OTLP.Traces.CheckCert {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		exporter, err = otlptracegrpc.New(ctx, opts...)
	default:
		opts := []otlptracehttp.Option{}
		if !config.OTLP.Traces.CheckCert {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptracehttp.New(ctx, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Traces exporter: %v", err)
	}

	withBatcher := sdktrace.WithBatcher(exporter)
	if config.OTLP.Traces.Synced {
		withBatcher = sdktrace.WithSyncer(exporter)
	}
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(newResource()),
		withBatcher,
	)
	otel.SetTracerProvider(tracerProvider)

	return tracerProvider.Shutdown, nil
}

func OTLPTracesInit(client *Client, config *types.Configuration, ctx context.Context) (func(), error) {
	// As config.OTLP.Traces fields may have been set by our own config (e.g. YAML),
	// we need to set SDK environment variables accordingly.
	os.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", strings.TrimSpace(config.OTLP.Traces.Endpoint))
	if config.OTLP.Traces.Protocol != "" {
		os.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", strings.TrimSpace(config.OTLP.Traces.Protocol))
	}
	if config.OTLP.Traces.Headers != "" {
		os.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", strings.TrimSpace(config.OTLP.Traces.Headers))
	}
	if config.OTLP.Traces.Timeout != 0 {
		os.Setenv("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", fmt.Sprintf("%d", config.OTLP.Traces.Timeout))
	}
	if len(config.OTLP.Traces.ExtraEnvVars) != 0 {
		for i, j := range config.OTLP.Traces.ExtraEnvVars {
			os.Setenv(i, j)
		}
	}
	// Registers a tracer Provider globally.
	shutdown, err := installTracesExportPipeline(config, ctx)
	if err != nil {
		return nil, err
	}
	shutDownCallback := func() {
		if err := shutdown(ctx); err != nil {
			utils.Log(utils.ErrorLvl, "OTLP Traces", err.Error())

		}
	}
	return shutDownCallback, nil
}
