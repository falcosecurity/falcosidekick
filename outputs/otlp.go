package outputs

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
	"go.opentelemetry.io/otel/trace"
)

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

type Context struct {
	TraceID trace.TraceID `json:"trace_id,omitempty"`
	SpanID  trace.SpanID  `json:"span_id,omitempty"`
}

type Attribute struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type Event struct {
	Name       string      `json:"name,omitempty"`
	Timestamp  string      `json:"timestamp,omitempty"`
	Attributes []Attribute `json:"attributes,omitempty"`
}

type Trace struct {
	Name       string         `json:"name,omitempty"`
	Context    Context        `json:"context,omitempty"`
	ParentID   *trace.TraceID `json:"parent_id,omitempty"`
	StartTime  string         `json:"start_time,omitempty"`
	EndTime    string         `json:"end_time,omitempty"`
	Attributes []Attribute    `json:"attributes,omitempty"`
	Events     []Event        `json:"events,omitempty"`
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

	trace := Trace{
		Name:      "falco",
		Context:   Context{TraceID: traceId, SpanID: spanId},
		ParentID:  nil,
		StartTime: falcopayload.Time.Format(time.RFC3339),
		EndTime:   falcopayload.Time.Format(time.RFC3339),
	}
	trace.Attributes = []Attribute{}

	evtAttribs := []Attribute{
		{
			Key:   "uuid",
			Value: falcopayload.UUID,
		},
		{
			Key:   "source",
			Value: falcopayload.Source,
		},
		{
			Key:   "priority",
			Value: falcopayload.Priority.String(),
		},
		{
			Key:   "rule",
			Value: falcopayload.Rule,
		},
		{
			Key: "output",
			// This is the full log line, which can be further
			// parsed and broken down into individual fields.
			Value: falcopayload.Output,
		},
		{
			Key:   "hostname",
			Value: falcopayload.Hostname,
		},
		{
			Key:   "tags",
			Value: strings.Join(falcopayload.Tags, ","),
		},
	}
	for k, v := range falcopayload.OutputFields {
		evtAttribs = append(evtAttribs, Attribute{Key: k, Value: fmt.Sprintf("%v", v)})
	}

	events := []Event{
		{
			"falcosidekick.otlp",
			falcopayload.Time.Format(time.RFC3339),
			evtAttribs,
		},
	}
	trace.Events = events

	log.Print("OTLP payload generated successfully")

	return &trace
}

func marshalJSON(trace *Trace) ([]byte, error) {
	result, err := json.Marshal(trace)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) OTLPPost(falcopayload types.FalcoPayload) {
	trace := newTrace(falcopayload)
	if trace == nil {
		log.Printf("Error generating trace")
		return
	}
	// NB: no need to marshalJSON(trace), as c.Post() takes care of that
	err := c.Post(trace)
	if err != nil {
		log.Printf("Error sending trace to OTLP endpoint: %v", err)
		return
	}
}
