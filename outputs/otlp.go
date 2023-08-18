package outputs

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Unit-testing helper
var getTracerProvider = otel.GetTracerProvider

// newTrace returns a new Trace object.
func newTrace(falcopayload types.FalcoPayload, durationMs int64) *trace.Span {
	_, exists := falcopayload.OutputFields["container.id"]
	if !exists {
		log.Printf("Error getting container id from output fields")
		return nil
	}

	startTime := falcopayload.Time
	endTime := falcopayload.Time.Add(time.Millisecond * time.Duration(durationMs))

	// https://www.w3.org/TR/trace-context/#trace-id
	containerID, ok := falcopayload.OutputFields["container.id"].(string)
	if !ok {
		log.Printf("Error converting container id to string")
		return nil
	}

	traceId, err := generateTraceID(containerID)
	if err != nil {
		log.Printf("Error generating trace id: %v for container id: %s", err, containerID)
		return nil
	}
	sc := trace.SpanContext{}.WithTraceID(traceId)
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
	span.SetAttributes(attribute.String("tags", strings.Join(falcopayload.Tags, ",")))
	for k, v := range falcopayload.OutputFields {
		span.SetAttributes(attribute.String(k, fmt.Sprintf("%v", v)))
	}
	//span.AddEvent("falco-event")
	span.End(trace.WithTimestamp(endTime))

	log.Printf("OTLP payload generated successfully for traceid=%s", span.SpanContext().TraceID())

	return &span
}

func (c *Client) OTLPPost(falcopayload types.FalcoPayload) {
	trace := newTrace(falcopayload, c.Config.OTLP.Traces.Duration)
	if trace == nil {
		log.Printf("Error generating trace")
		return
	}
}

func generateTraceID(containerID string) (trace.TraceID, error) {
	if containerID == "" {
		// Generate a random 32 character string
		randomInt, err := rand.Int(rand.Reader, big.NewInt(
			100000000000000001,
		))
		if err != nil {
			log.Print("Error generating random number")
			return trace.TraceIDFromHex("100000000000000001")
		}
		containerID = fmt.Sprintf("%032d", randomInt)
	}
	// Pad the containerID to 32 characters
	for len(containerID) < 32 {
		containerID = "0" + containerID
	}
	return trace.TraceIDFromHex(containerID)
}
