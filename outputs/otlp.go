package outputs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"log"
	"strings"
	"text/template"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Unit-testing helper
var getTracerProvider = otel.GetTracerProvider

// newTrace returns a new Trace object.
func (c *Client) newTrace(falcopayload types.FalcoPayload) *trace.Span {
	traceID, _, err := generateTraceID(falcopayload, c.Config)
	if err != nil {
		log.Printf("[ERROR] : Error generating trace id: %v for output fields %v", err, falcopayload.OutputFields)
		return nil
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
	// span.AddEvent("falco-event")
	span.End(trace.WithTimestamp(endTime))

	if c.Config.Debug {
		log.Printf("[DEBUG] : OTLP payload generated successfully for traceid=%s", span.SpanContext().TraceID())
	}

	return &span
}

// OTLPPost generates an OTLP trace _implicitly_ via newTrace() by
// calling OTEL SDK's tracer.Start() --> span.End(), i.e. no need to explicitly
// do a HTTP POST
func (c *Client) OTLPPost(falcopayload types.FalcoPayload) {
	trace := c.newTrace(falcopayload)
	if trace == nil {
		log.Printf("[ERROR] : Error generating trace")
		return
	}
}

const (
	templateOption       = "missingkey=zero"
	kubeTemplateStr      = `{{.cluster}}{{.k8s_pod_name}}{{.k8s_ns_name}}{{.k8s_container_name}}`
	containerTemplateStr = `{{.container_id}}`
)

var (
	kubeTemplate      = template.Must(template.New("").Option(templateOption).Parse(kubeTemplateStr))
	containerTemplate = template.Must(template.New("").Option(templateOption).Parse(containerTemplateStr))
)

func sanitizeOutputFields(falcopayload types.FalcoPayload) map[string]string {
	ret := make(map[string]string)
	for k, v := range falcopayload.OutputFields {
		k := strings.Replace(k, ".", "_", -1)
		ret[k] = fmt.Sprintf("%v", v)
	}
	return ret
}

func renderTraceIDFromTemplate(falcopayload types.FalcoPayload, config *types.Configuration) (string, string) {
	tplStr := config.OTLP.Traces.TraceIDFormat
	tpl := config.OTLP.Traces.TraceIDFormatTemplate
	outputFields := sanitizeOutputFields(falcopayload)
	if tplStr == "" {
		switch {
		case outputFields["cluster"] != "" &&
			outputFields["k8s_pod_name"] != "" &&
			outputFields["k8s_ns_name"] != "" &&
			outputFields["k8s_container_name"] != "":
			tpl, tplStr = kubeTemplate, kubeTemplateStr
		default:
			tpl, tplStr = containerTemplate, containerTemplateStr
		}
	}
	buf := &bytes.Buffer{}
	if err := tpl.Execute(buf, outputFields); err != nil {
		log.Printf("[WARNING] : OTLP - Error expanding template: %v", err)
	}
	return buf.String(), tplStr
}

func generateTraceID(falcopayload types.FalcoPayload, config *types.Configuration) (trace.TraceID, string, error) {
	var traceID trace.TraceID
	var err error
	traceIDStr, tplStr := renderTraceIDFromTemplate(falcopayload, config)

	if traceIDStr != "" {
		// Hash the returned template- rendered string to generate a 32 character traceID
		hash := fnv.New128a()
		hash.Write([]byte(traceIDStr))
		digest := hash.Sum(nil)
		traceIDStr = hex.EncodeToString(digest[:])
	} else {
		// Template produced no string :(, generate a random 32 character string
		traceIDStr, err = randomHex(16)
		if err != nil {
			return traceID, "", err
		}
	}
	traceID, err = trace.TraceIDFromHex(traceIDStr)
	return traceID, tplStr, err
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
