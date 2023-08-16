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

func installExportPipeline(ctx context.Context) (func(context.Context) error, error) {
	client := otlptracehttp.NewClient(
		otlptracehttp.WithInsecure(),
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

type otlpEnv struct {
	EnvName string
	Path    string
}

func otlpSetEnv(target string, envs []otlpEnv) string {
	var value string
	for _, v := range envs {
		if os.Getenv(v.EnvName) != "" {
			value = os.Getenv(v.EnvName) + v.Path
			os.Setenv(target, value)
			break
		}
	}
	return value
}

// See https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/
// FYI for traces, you can also use:
// - OTEL_EXPORTER_OTLP_HEADERS, OTEL_EXPORTER_OTLP_TRACES_HEADERS
// - OTEL_EXPORTER_OTLP_TIMEOUT, OTEL_EXPORTER_OTLP_TRACES_TIMEOUT
// - OTEL_EXPORTER_OTLP_PROTOCOL, OTEL_EXPORTER_OTLP_TRACES_PROTOCOL
func otlpSetEnvs() {
	otlpTracesEp := otlpSetEnv("OTLP_TRACES_ENDPOINT", []otlpEnv{
		{EnvName: "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", Path: ""},
		{EnvName: "OTEL_EXPORTER_OTLP_ENDPOINT", Path: "/v1/traces"},
	})
	if otlpTracesEp != "" {
		log.Printf("[INFO] : OTLP.Traces endpoint=%s\n", otlpTracesEp)
	}
}
