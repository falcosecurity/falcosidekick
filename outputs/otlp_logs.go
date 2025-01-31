package outputs

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

func NewOtlpLogsClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	initClientArgs := &types.InitClientArgs{
		Config:          config,
		Stats:           stats,
		DogstatsdClient: dogstatsdClient,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
	}
	otlpClient, err := NewClient("OTLP Logs", config.OTLP.Logs.Endpoint, types.CommonConfig{}, *initClientArgs)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	loggerProvider, err := OTLPLogsInit(ctx, config)
	if err != nil {
		utils.Log(utils.ErrorLvl, "OTLP Logs", fmt.Sprintf("Error Logger creation: %v", err))
		return nil, err
	}

	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		utils.Log(utils.ErrorLvl, "OTLP", err.Error())
	}))

	utils.Log(utils.InfoLvl, "OTLP Logs", "Client created")
	otlpClient.ShutDownFunc = func() {
		if err := loggerProvider.Shutdown(ctx); err != nil {
			utils.Log(utils.ErrorLvl, "OTLP Logs", err.Error())
		}
	}

	otlpClient.OTLPLogsLogger = otelslog.NewLogger("falco", otelslog.WithLoggerProvider(loggerProvider))

	return otlpClient, nil
}

func OTLPLogsInit(ctx context.Context, config *types.Configuration) (*sdklog.LoggerProvider, error) {
	// As config.OTLP.Logs fields may have been set by our own config (e.g. YAML),
	// we need to set SDK environment variables accordingly.
	os.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", strings.TrimSpace(config.OTLP.Logs.Endpoint))
	if config.OTLP.Logs.Protocol != "" {
		os.Setenv("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", strings.TrimSpace(config.OTLP.Logs.Protocol))
	}
	if config.OTLP.Logs.Headers != "" {
		os.Setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", strings.TrimSpace(config.OTLP.Logs.Headers))
	}
	if config.OTLP.Logs.Timeout != 0 {
		os.Setenv("OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", fmt.Sprintf("%d", config.OTLP.Logs.Timeout))
	}
	if len(config.OTLP.Logs.ExtraEnvVars) != 0 {
		for i, j := range config.OTLP.Logs.ExtraEnvVars {
			os.Setenv(i, j)
		}
	}

	var exporter sdklog.Exporter
	var err error
	switch config.OTLP.Logs.Protocol {
	case GRPC:
		opts := []otlploggrpc.Option{}
		if !config.OTLP.Traces.CheckCert {
			opts = append(opts, otlploggrpc.WithInsecure())
		}
		exporter, err = otlploggrpc.New(ctx, opts...)
	default:
		opts := []otlploghttp.Option{}
		if !config.OTLP.Traces.CheckCert {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		exporter, err = otlploghttp.New(ctx, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create Logs exporter: %v", err)
	}

	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(
			sdklog.NewBatchProcessor(exporter),
		),
		sdklog.WithResource(newResource()),
	)

	return loggerProvider, nil
}

func (c *Client) OTLPLogsPost(falcopayload types.FalcoPayload) {
	c.OTLPLogsLogger.Info(
		falcopayload.Output,
		"priority", falcopayload.Priority.String(),
		"source", falcopayload.Source,
		"rule", falcopayload.Rule,
		"hostname", falcopayload.Hostname,
		"tags", strings.Join(falcopayload.Tags, ","),
		slog.String("timestamp", falcopayload.Time.String()),
	)

	utils.Log(utils.InfoLvl, c.OutputType, "Sending log")
}
