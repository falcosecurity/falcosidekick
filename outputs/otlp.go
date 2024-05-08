// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Unit-testing helper
var getTracerProvider = otel.GetTracerProvider

func NewOtlpTracesClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	initClientArgs := &types.InitClientArgs{
		Config:          config,
		Stats:           stats,
		DogstatsdClient: dogstatsdClient,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
	}
	otlpClient, err := NewClient("OTLPTraces", config.OTLP.Traces.Endpoint, false, false, *initClientArgs)
	if err != nil {
		return nil, err
	}
	shutDownFunc, err := otlpInit(config)
	if err != nil {
		log.Printf("[ERROR] : OLTP Traces - Error client creation: %v\n", err)
		return nil, err
	}
	log.Printf("[INFO]  : OTLP Traces - %+v\n", config.OTLP.Traces)
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
	span.SetAttributes(attribute.String("output", falcopayload.Output))
	span.SetAttributes(attribute.String("hostname", falcopayload.Hostname))
	span.SetAttributes(attribute.StringSlice("tags", falcopayload.Tags))
	for k, v := range falcopayload.OutputFields {
		span.SetAttributes(attribute.String(k, fmt.Sprintf("%v", v)))
	}
	span.End(trace.WithTimestamp(endTime))

	if c.Config.Debug {
		log.Printf("[DEBUG] : OTLP Traces - payload generated successfully for traceid=%s", span.SpanContext().TraceID())
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
		go c.CountMetric(Outputs, 1, []string{"output:otlptraces", "status:error"})
		c.Stats.OTLPTraces.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "otlptraces", "status": Error}).Inc()
		log.Printf("[ERROR] : OLTP Traces - Error generating trace: %v\n", err)
		return
	}
	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:otlptraces", "status:ok"})
	c.Stats.OTLPTraces.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "otlptraces", "status": OK}).Inc()
	log.Println("[INFO]  : OLTP Traces - OK")
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
