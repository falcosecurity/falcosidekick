package otlpmetrics

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.23.1"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
)

const (
	meterName      = "falcosecurity.falco.otlpmetrics.meter"
	serviceName    = "falco"
	serviceVersion = "0.1.0"
)

// TODO: move logging logic out of this context

// Config represents config parameters for OTLP Metrics
type Config struct {
	Endpoint            string
	Protocol            string
	Timeout             int64
	Headers             string
	ExtraEnvVars        map[string]string
	CheckCert           bool
	MinimumPriority     string
	ExtraAttributes     string
	ExtraAttributesList []string
}

// InitProvider initializes a new OTLP Metrics Provider. It returns a function to shut down it.
func InitProvider(ctx context.Context, config *Config) (func(ctx context.Context) error, error) {
	restoreEnvironment, err := initEnvironment(config)
	if err != nil {
		return nil, fmt.Errorf("failed to init environemt: %v", err)
	}
	defer restoreEnvironment()

	shutdownFunc, err := initMeterProvider(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create meter provider: %v", err)
	}

	return shutdownFunc, nil
}

// initEnvironment initializes the proper environment variables to the corresponding config values. If an environment
// variable is already set, it's value is left uncharged. It returns a function to restore the previous environment
// context.
func initEnvironment(config *Config) (cleanupFunc func(), err error) {
	cleanupFuncs := make([]func(), 0, 5)
	defer func() {
		if err != nil {
			for _, fn := range cleanupFuncs {
				fn()
			}
		}
	}()

	var unsetEnv func()
	// As OTLPMetrics fields may have been set by our own config (e.g. YAML), We need to set SDK environment variables
	// accordingly.
	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"); endpoint == "" {
		unsetEnv, err = setEnv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", strings.TrimSpace(config.Endpoint))
		if err != nil {
			return nil, err
		}
		cleanupFuncs = append(cleanupFuncs, unsetEnv)
	}

	if protocol := os.Getenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"); protocol == "" {
		unsetEnv, err = setEnv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", strings.TrimSpace(config.Protocol))
		if err != nil {
			return nil, err
		}
		cleanupFuncs = append(cleanupFuncs, unsetEnv)
	}

	if headers := os.Getenv("OTEL_EXPORTER_OTLP_METRICS_HEADERS"); headers == "" {
		unsetEnv, err = setEnv("OTEL_EXPORTER_OTLP_METRICS_HEADERS", strings.TrimSpace(config.Headers))
		if err != nil {
			return nil, err
		}
		cleanupFuncs = append(cleanupFuncs, unsetEnv)
	}

	if timeout := os.Getenv("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT"); timeout == "" {
		unsetEnv, err = setEnv("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", fmt.Sprintf("%d", config.Timeout))
		if err != nil {
			return nil, err
		}
		cleanupFuncs = append(cleanupFuncs, unsetEnv)
	}

	for envVar, value := range config.ExtraEnvVars {
		if configValue := os.Getenv(envVar); configValue != "" {
			continue
		}
		unsetEnv, err = setEnv(envVar, value)
		if err != nil {
			return nil, err
		}
		cleanupFuncs = append(cleanupFuncs, unsetEnv)
	}

	return func() {
		for _, fn := range cleanupFuncs {
			fn()
		}
	}, nil
}

func setEnv(envVar, value string) (func(), error) {
	if err := os.Setenv(envVar, value); err != nil {
		return nil, fmt.Errorf("failed to set %v to %v: %v", envVar, value, err)
	}
	return func() {
		if err := os.Setenv(envVar, ""); err != nil {
			utils.Log(utils.ErrorLvl, "OTLP Metrics", fmt.Sprintf("Error unsetting env variable %q: %v", envVar, err))
		}
	}, nil
}

// initMeterProvider initializes an OTEL meter provider (and the corresponding exporter). It returns a function to shut
// down the meter provider.
func initMeterProvider(ctx context.Context, config *Config) (func(context.Context) error, error) {
	var err error
	var metricExporter sdkmetric.Exporter
	switch protocol := config.Protocol; protocol {
	case "grpc":
		metricExporter, err = createGRPCExporter(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC exporter: %v", err)
		}
	case "http/protobuf":
		metricExporter, err = createHTTPExporter(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP exporter: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported OTLP transport protocol: %s", protocol)
	}

	res, err := sdkresource.New(ctx,
		sdkresource.WithSchemaURL(semconv.SchemaURL),
		sdkresource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %v", err)
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(res),
	)

	otel.SetMeterProvider(meterProvider)
	return meterProvider.Shutdown, nil
}

func createGRPCExporter(ctx context.Context, config *Config) (sdkmetric.Exporter, error) {
	var options []otlpmetricgrpc.Option
	if !config.CheckCert {
		options = append(options, otlpmetricgrpc.WithInsecure())
	}

	return otlpmetricgrpc.New(ctx, options...)
}

func createHTTPExporter(ctx context.Context, config *Config) (sdkmetric.Exporter, error) {
	var options []otlpmetrichttp.Option
	if !config.CheckCert {
		options = append(options, otlpmetrichttp.WithInsecure())
	}
	return otlpmetrichttp.New(ctx, options...)
}

type Counter interface {
	With(attributes ...attribute.KeyValue) Counter
	Inc()
}

type OTLPMetrics struct {
	Falco   Counter
	Inputs  Counter
	Outputs Counter
}

type counterInstrument struct {
	name                string
	description         string
	supportedAttributes map[string]struct{}
	attributes          []attribute.KeyValue
}

func NewCounter(name string, description string, supportedAttributes []string) Counter {
	counter := &counterInstrument{
		name:                name,
		description:         description,
		supportedAttributes: make(map[string]struct{}),
	}
	for _, attr := range supportedAttributes {
		counter.supportedAttributes[attr] = struct{}{}
	}
	return counter
}

func (c *counterInstrument) With(attributes ...attribute.KeyValue) Counter {
	filteredAttributes := c.filterAttributes(attributes)
	counter := &counterInstrument{
		name:                c.name,
		supportedAttributes: c.supportedAttributes,
		attributes:          append(c.attributes, filteredAttributes...),
	}
	return counter
}

func (c *counterInstrument) filterAttributes(attributes []attribute.KeyValue) []attribute.KeyValue {
	filteredAttributes := make([]attribute.KeyValue, 0, len(c.attributes))
	for _, attr := range attributes {
		if _, ok := c.supportedAttributes[string(attr.Key)]; ok {
			filteredAttributes = append(filteredAttributes, attr)
		}
	}
	return filteredAttributes
}

func (c *counterInstrument) Inc() {
	meter := otel.Meter(meterName)
	ruleCounter, err := meter.Int64Counter(c.name, metric.WithDescription(c.description))
	if err != nil {
		utils.Log(utils.ErrorLvl, "OTLP Metrics", fmt.Sprintf("Error generating metric: %v", err))
		return
	}

	ruleCounter.Add(context.Background(), 1, metric.WithAttributes(c.attributes...))
}
