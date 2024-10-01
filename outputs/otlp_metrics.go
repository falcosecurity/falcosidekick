package outputs

import (
	"context"
	"fmt"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.23.1"
	"log"
	"os"
	"strings"
)

// TODO: move logging logic out of this context

// NewOTLPMetricsClient creates a new OTLP Metrics Client.
func NewOTLPMetricsClient(ctx context.Context, config *types.Configuration, stats *types.Statistics,
	promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	initClientArgs := &types.InitClientArgs{
		Config:          config,
		Stats:           stats,
		DogstatsdClient: dogstatsdClient,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
	}

	cfg := &config.OTLP.Metrics
	otlpClient, err := NewClient("OTLPMetrics", cfg.Endpoint, types.CommonConfig{}, *initClientArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to create output client: %v", err)
	}

	restoreEnvironment, err := initEnvironment(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to init environemt: %v", err)
	}
	defer restoreEnvironment()

	shutdownFunc, err := initMeterProvider(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create meter provider: %v", err)
	}

	otlpClient.ShutDownFunc = func() {
		if err := shutdownFunc(ctx); err != nil {
			log.Printf("[ERROR] : OTLP Metrics - Error: %v\n", err)
		}
	}
	return otlpClient, nil
}

// initEnvironment initializes the proper environment variables to the corresponding config values. If an environment
// variable is already set, it's value is left uncharged. It returns a function to restore the previous environment
// context.
func initEnvironment(config *types.OTLPMetrics) (cleanupFunc func(), err error) {
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
			log.Printf("[ERROR] : OTLP Metrics - Error unsetting env variable %q: %v\n", envVar, err)
		}
	}, nil
}

const (
	meterName      = "falcosecurity.falco.otlp.meter"
	serviceName    = "falco"
	serviceVersion = "0.1.0"
)

// initMeterProvider initializes an OTEL meter provider (and the corresponding exporter). It returns a function to shut
// down the meter provider.
func initMeterProvider(ctx context.Context, config *types.OTLPMetrics) (func(context.Context) error, error) {
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

func createGRPCExporter(ctx context.Context, config *types.OTLPMetrics) (sdkmetric.Exporter, error) {
	var options []otlpmetricgrpc.Option
	if config.CheckCert == false {
		options = append(options, otlpmetricgrpc.WithInsecure())
	}

	return otlpmetricgrpc.New(ctx, options...)
}

func createHTTPExporter(ctx context.Context, config *types.OTLPMetrics) (sdkmetric.Exporter, error) {
	var options []otlpmetrichttp.Option
	if config.CheckCert == false {
		options = append(options, otlpmetrichttp.WithInsecure())
	}
	return otlpmetrichttp.New(ctx, options...)
}

const (
	metricName                 = "falcosecurity_falco_rules_matches_total"
	metricDescription          = "Number of times rules match"
	metricAttributeUUIDKey     = "uuid"
	metricAttributeSourceKey   = "source"
	metricAttributePriorityKey = "priority"
	metricAttributeRuleKey     = "rule"
	metricAttributeHostnameKey = "hostname"
	metricAttributeTagsKey     = "tags"
)

// OTLPMetricsPost generates a new OTEL metric data point for the provided falco payload.
func (c *Client) OTLPMetricsPost(falcoPayload types.FalcoPayload) {
	c.Stats.OTLPMetrics.Add(Total, 1)

	meter := otel.Meter(meterName)
	ruleCounter, err := meter.Int64Counter(metricName, metric.WithDescription(metricDescription))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:otlpmetrics", "status:error"})
		c.Stats.OTLPMetrics.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "otlpmetrics", "status": Error}).Inc()
		log.Printf("[ERROR] : OTLP Metrics - Error generating metric: %v\n", err)
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String(metricAttributeUUIDKey, falcoPayload.UUID),
		attribute.String(metricAttributeSourceKey, falcoPayload.Source),
		attribute.String(metricAttributePriorityKey, falcoPayload.Priority.String()),
		attribute.String(metricAttributeRuleKey, falcoPayload.Rule),
		attribute.String(metricAttributeHostnameKey, falcoPayload.Hostname),
		attribute.StringSlice(metricAttributeTagsKey, falcoPayload.Tags),
	}
	ruleCounter.Add(context.Background(), 1, metric.WithAttributes(attrs...))
	go c.CountMetric(Outputs, 1, []string{"output:otlpmetrics", "status:ok"})
	c.Stats.OTLPMetrics.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "otlpmetrics", "status": OK}).Inc()
	log.Println("[INFO]  : OTLP Metrics - OK")
}
