package outputs

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
	"go.opentelemetry.io/otel/trace"
)

type StringValue struct {
	Value string `json:"stringValue,omitempty"`
}

type Attribute struct {
	Key   string      `json:"key,omitempty"`
	Value StringValue `json:"value,omitempty"`
}

type Event struct {
	Name                   string      `json:"name,omitempty"`
	Timestamp              int64       `json:"timeUnixNano,omitempty"`
	Attributes             []Attribute `json:"attributes,omitempty"`
	DroppedAttributesCount uint32      `json:"droppedAttributesCount,omitempty"`
}

type Link struct {
	TraceID                trace.TraceID    `json:"traceId,omitempty"`
	SpanID                 trace.SpanID     `json:"spanId,omitempty"`
	TraceState             trace.TraceState `json:"traceState,omitempty"`
	Attributes             []Attribute      `json:"attributes,omitempty"`
	DroppedAttributesCount uint32           `json:"droppedAttributesCount,omitempty"`
}

type Status struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type Span struct {
	TraceID                trace.TraceID    `json:"traceId,omitempty"`
	SpanID                 trace.SpanID     `json:"spanId,omitempty"`
	TraceState             trace.TraceState `json:"traceState,omitempty"`
	Kind                   trace.SpanKind   `json:"kind,omitempty"`
	ParentSpanID           *trace.TraceID   `json:"parentSpanId,omitempty"`
	Name                   string           `json:"name,omitempty"`
	StartTime              int64            `json:"startTimeUnixNano,omitempty"`
	EndTime                int64            `json:"endTimeUnixNano,omitempty"`
	Attributes             []Attribute      `json:"attributes,omitempty"`
	DroppedAttributesCount uint32           `json:"droppedAttributesCount,omitempty"`
	Events                 []Event          `json:"events,omitempty"`
	Links                  []Link           `json:"links,omitempty"`
	DroppedLinksCount      uint32           `json:"droppedLinksCount,omitempty"`
	Status                 Status           `json:"status,omitempty"`
}

type Resource struct {
	Attributes []Attribute `json:"attributes,omitempty"`
}

type ResourceSpan struct {
	Resource   Resource    `json:"resource,omitempty"`
	ScopeSpans []ScopeSpan `json:"scopeSpans,omitempty"`
	SchemaURL  string      `json:"schemaUrl,omitempty"`
}

type Scope struct {
	Name       string      `json:"name,omitempty"`
	Version    string      `json:"version,omitempty"`
	Attributes []Attribute `json:"attributes,omitempty"`
}

type ScopeSpan struct {
	Scope     Scope  `json:"scope,omitempty"`
	Spans     []Span `json:"spans,omitempty"`
	SchemaURL string `json:"schemaUrl,omitempty"`
}

type Trace struct {
	ResourceSpans []ResourceSpan `json:"resourceSpans,omitempty"`
}

// newTrace returns a new Trace object.
func newTrace(falcopayload types.FalcoPayload) *Trace {
	_, exists := falcopayload.OutputFields["container.id"]
	if !exists {
		log.Printf("Error getting container id from output fields")
		return nil
	}
	containerID, ok := falcopayload.OutputFields["container.id"].(string)
	if !ok {
		log.Printf("Error converting container id to string")
		return nil
	}

	// https://www.w3.org/TR/trace-context/#trace-id
	traceId, err := generateTraceID(containerID)
	if err != nil {
		log.Printf("Error generating trace id: %v", err)
		return nil
	}

	spanId, err := generateSpanID("")
	if err != nil {
		log.Printf("Error generating span id: %v", err)
		return nil
	}

	span := Span{
		Name:         falcopayload.Rule,
		TraceID:      traceId,
		SpanID:       spanId,
		ParentSpanID: nil,
		TraceState:   trace.TraceState{},
		StartTime:    falcopayload.Time.UnixNano(),
		EndTime:      falcopayload.Time.UnixNano(),
		Kind:         trace.SpanKindServer,
	}
	span.Attributes = []Attribute{}

	evtAttribs := []Attribute{
		{
			Key:   "uuid",
			Value: StringValue{Value: falcopayload.UUID},
		},
		{
			Key:   "source",
			Value: StringValue{Value: falcopayload.Source},
		},
		{
			Key:   "priority",
			Value: StringValue{Value: falcopayload.Priority.String()},
		},
		{
			Key:   "rule",
			Value: StringValue{Value: falcopayload.Rule},
		},
		{
			Key: "output",
			// This is the full log line, which can be further
			// parsed and broken down into individual fields.
			Value: StringValue{Value: falcopayload.Output},
		},
		{
			Key:   "hostname",
			Value: StringValue{Value: falcopayload.Hostname},
		},
		{
			Key:   "tags",
			Value: StringValue{Value: strings.Join(falcopayload.Tags, ",")},
		},
	}
	for k, v := range falcopayload.OutputFields {
		evtAttribs = append(evtAttribs,
			Attribute{Key: k, Value: StringValue{Value: fmt.Sprintf("%v", v)}})
	}

	span.Events = []Event{
		{
			Name:       "falcosidekick.otlp",
			Timestamp:  falcopayload.Time.UnixNano(),
			Attributes: evtAttribs,
		},
	}

	trace := Trace{
		ResourceSpans: []ResourceSpan{
			{
				Resource: Resource{
					Attributes: []Attribute{
						{
							Key:   "service.name",
							Value: StringValue{Value: "falcosidekick.otlp"},
						},
					},
				},
				ScopeSpans: []ScopeSpan{
					{
						Scope: Scope{
							Name:    "falcosidekick-otlp",
							Version: "1.0.0",
						},
						Spans: []Span{span},
					},
				},
			},
		},
	}

	log.Print("OTLP payload generated successfully")

	return &trace
}

func (c *Client) OTLPPost(falcopayload types.FalcoPayload) {
	trace := newTrace(falcopayload)
	if trace == nil {
		log.Printf("Error generating trace")
		return
	}
	if c.Config.OTLP.User != "" && c.Config.OTLP.APIKey != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.BasicAuth(c.Config.OTLP.User, c.Config.OTLP.APIKey)
	}
	err := c.Post(trace)
	if err != nil {
		log.Printf("Error sending trace to OTLP endpoint: %v", err)
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

func generateSpanID(containerID string) (trace.SpanID, error) {
	if containerID == "" {
		// Generate a random 16 character string
		randomInt, err := rand.Int(rand.Reader, big.NewInt(10000000000000000))
		if err != nil {
			log.Print("Error generating random number")
			return trace.SpanIDFromHex("10000000000000000")
		}
		containerID = fmt.Sprintf("%016d", randomInt)
	}

	// Pad the containerID to 16 characters
	for len(containerID) < 16 {
		containerID = "0" + containerID
	}
	return trace.SpanIDFromHex(containerID)
}
