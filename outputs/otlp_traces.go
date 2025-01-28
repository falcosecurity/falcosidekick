// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// Unit-testing helper
var getTracerProvider = otel.GetTracerProvider

func NewOtlpTracesClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	initClientArgs := &types.InitClientArgs{
		Config:          config,
		Stats:           stats,
		DogstatsdClient: dogstatsdClient,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
	}
	otlpClient, err := NewClient("OTLP Traces", config.OTLP.Traces.Endpoint, types.CommonConfig{}, *initClientArgs)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	shutDownFunc, err := OTLPTracesInit(otlpClient, config, ctx)
	if err != nil {
		utils.Log(utils.ErrorLvl, "OTLP Traces", fmt.Sprintf("Error client creation: %v", err))
		return nil, err
	}

	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		utils.Log(utils.ErrorLvl, "OTLP", err.Error())
	}))

	utils.Log(utils.InfoLvl, "OTLP Traces", "Client created")
	otlpClient.ShutDownFunc = shutDownFunc
	return otlpClient, nil
}

// newTrace returns a new Trace object.
func (c *Client) newTrace(falcopayload types.FalcoPayload) (*trace.Span, error) {
	traceID, err := generateTraceID(falcopayload)
	if err != nil {
		return nil, err
	}

	startTime := falcopayload.Time
	endTime := falcopayload.Time.Add(time.Millisecond * time.Duration(c.Config.OTLP.Traces.Duration))

	sc := trace.SpanContext{}.WithTraceID(traceID)
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	tracer := getTracerProvider().Tracer("falco-event")
	_, span := tracer.Start(
		ctx,
		falcopayload.Rule,
		trace.WithTimestamp(startTime),
		trace.WithSpanKind(trace.SpanKindServer))

	span.SetAttributes(attribute.String("uuid", falcopayload.UUID))
	span.SetAttributes(attribute.String("source", falcopayload.Source))
	span.SetAttributes(attribute.String("priority", falcopayload.Priority.String()))
	span.SetAttributes(attribute.String("rule", falcopayload.Rule))
	span.SetAttributes(attribute.String("hostname", falcopayload.Hostname))
	span.SetAttributes(attribute.StringSlice("tags", falcopayload.Tags))
	for k, v := range falcopayload.OutputFields {
		span.SetAttributes(attribute.String(k, fmt.Sprintf("%v", v)))
	}
	span.AddEvent(falcopayload.Output, trace.EventOption(trace.WithTimestamp(falcopayload.Time)))
	span.End(trace.WithTimestamp(endTime))

	if c.Config.Debug {
		utils.Log(utils.DebugLvl, c.OutputType, fmt.Sprintf("Payload generated successfully for traceid=%s", span.SpanContext().TraceID()))
	}

	return &span, nil
}

// OTLPPost generates an OTLP trace _implicitly_ via newTrace() by
// calling OTEL SDK's tracer.Start() --> span.End(), i.e. no need to explicitly
// do a HTTP POST
func (c *Client) OTLPTracesPost(falcopayload types.FalcoPayload) {
	c.Stats.OTLPTraces.Add(Total, 1)

	_, err := c.newTrace(falcopayload)
	if err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Error generating trace: %v", err))
		return
	}
	utils.Log(utils.InfoLvl, c.OutputType, "Sending trace")
}

func generateTraceID(falcopayload types.FalcoPayload) (trace.TraceID, error) {
	var k8sNsName, k8sPodName, containerId, evtHostname string

	if falcopayload.OutputFields["k8s.ns.name"] != nil {
		k8sNsName = falcopayload.OutputFields["k8s.ns.name"].(string)
	}
	if falcopayload.OutputFields["k8s.pod.name"] != nil {
		k8sPodName = falcopayload.OutputFields["k8s.pod.name"].(string)
	}
	if falcopayload.OutputFields["container.id"] != nil {
		containerId = falcopayload.OutputFields["container.id"].(string)
	}
	if falcopayload.OutputFields["evt.hostname"] != nil {
		evtHostname = falcopayload.OutputFields["evt.hostname"].(string)
	}

	var traceIDStr string
	if k8sNsName != "" && k8sPodName != "" {
		traceIDStr = fmt.Sprintf("%v:%v", k8sNsName, k8sPodName)
	} else if containerId != "" && containerId != "host" {
		traceIDStr = containerId
	} else if evtHostname != "" {
		traceIDStr = evtHostname
	}

	if traceIDStr == "" {
		return trace.TraceID{}, errors.New("can't find any field to generate an immutable trace id")
	}

	// Hash to return a 32 character traceID
	hash := fnv.New128a()
	hash.Write([]byte(traceIDStr))
	digest := hash.Sum(nil)
	traceIDStr = hex.EncodeToString(digest)
	return trace.TraceIDFromHex(traceIDStr)
}
