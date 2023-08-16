package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
)

const (
	OTLPinstrumentationName    = "falcosidekick.otlp"
	OTLPinstrumentationVersion = "v0.1.0"
)

func newResource() *resource.Resource {
	return resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(OTLPinstrumentationName),
		semconv.ServiceVersion(OTLPinstrumentationVersion),
	)
}

const AuthorizationHeaderKey = "Authorization"

func installExportPipeline(ctx context.Context) (func(context.Context) error, error) {
	client := otlptracehttp.NewClient(
		otlptracehttp.WithInsecure(),
		//otlptracehttp.WithHeaders(WithBasicAuth("admin", "admin")),
	)
	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		//sdktrace.WithBatcher(exporter),
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(newResource()),
	)
	otel.SetTracerProvider(tracerProvider)

	return tracerProvider.Shutdown, nil
}

func otlpInit() func() {
	ctx := context.Background()
	// Registers a tracer Provider globally.
	shutdown, err := installExportPipeline(ctx)
	if err != nil {
		log.Fatal(err)
	}
	shutDownCallback := func() {
		if err := shutdown(ctx); err != nil {
			log.Fatal(err)
		}
	}
	return shutDownCallback
}

// OTEL_EXPORTER_OTLP_ENDPOINT
// OTEL_EXPORTER_OTLP_TRACES_HEADERS
func otlpEnv() {
	os.Setenv("OTLP_TRACES_ENDPOINT",
		os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
}
