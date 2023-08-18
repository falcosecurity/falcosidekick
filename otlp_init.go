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
	var client otlptrace.Client
	switch config.OTLP.Traces.Insecure {
	case true:
		client = otlptracehttp.NewClient(otlptracehttp.WithInsecure())
	case false:
		client = otlptracehttp.NewClient()
	}

	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
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
	Target  string
	EnvName string
	Path    string
}

// NB: create OS interface to allow unit-testing
type OS interface {
	Getenv(string) string
	Setenv(string, string) error
}

type defaultOS struct{}

func newDefaultOS() *defaultOS {
	return &defaultOS{}
}
func (defaultOS) Getenv(key string) string {
	return os.Getenv(key)
}
func (defaultOS) Setenv(key, value string) error {
	return os.Setenv(key, value)
}

var otlpOS OS = newDefaultOS()

func otlpSetEnv(envs []otlpEnv) string {
	var value string
	for _, v := range envs {
		if otlpOS.Getenv(v.EnvName) != "" {
			value = otlpOS.Getenv(v.EnvName) + v.Path
			otlpOS.Setenv(v.Target, value)
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
	otlpSetEnv([]otlpEnv{
		// Set OTLP_TRACES_ENDPOINT (used by config.OTLP.Traces) from SDK OTLP env vars
		{Target: "OTLP_TRACES_ENDPOINT", EnvName: "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", Path: ""},
		{Target: "OTLP_TRACES_ENDPOINT", EnvName: "OTEL_EXPORTER_OTLP_ENDPOINT", Path: "/v1/traces"},
		// Set OTEL_EXPORTER_OTLP_TRACES_ENDPOINT (SDK env) from OTLP_TRACES_ENDPOINT if user only set the latter
		{Target: "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", EnvName: "OTLP_TRACES_ENDPOINT", Path: ""},
	})
}
