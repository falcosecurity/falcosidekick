package outputs

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
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

	traceId, _, err := generateTraceID(falcopayload, c.Config)
	if err != nil {
		log.Printf("[ERROR] : Error generating trace id: %v for output fields %v", err, falcopayload.OutputFields)
		return nil
	}

	startTime := falcopayload.Time
	endTime := falcopayload.Time.Add(time.Millisecond * time.Duration(c.Config.OTLP.Traces.Duration))

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
	span.SetAttributes(attribute.StringSlice("tags", falcopayload.Tags))
	for k, v := range falcopayload.OutputFields {
		span.SetAttributes(attribute.String(k, fmt.Sprintf("%v", v)))
	}
	//span.AddEvent("falco-event")
	span.End(trace.WithTimestamp(endTime))

	if c.Config.Debug {
		log.Printf("[DEBUG] : OTLP payload generated successfully for traceid=%s", span.SpanContext().TraceID())
	}

	return &span
}

func (c *Client) OTLPPost(falcopayload types.FalcoPayload) {
	trace := c.newTrace(falcopayload)
	if trace == nil {
		log.Printf("[ERROR] : Error generating trace")
		return
	}
}

const (
	kubeTemplateStr      = `{{.cluster}}{{.k8s_pod_name}}{{.k8s_ns_name}}{{.k8s_container_name}}`
	containerTemplateStr = `{{index .container_id}}`
)

var (
	kubeTemplate      = template.Must(template.New("").Parse(kubeTemplateStr))
	containerTemplate = template.Must(template.New("").Parse(containerTemplateStr))
)

func sanitizeOutputFields(falcopayload types.FalcoPayload) map[string]string {
	ret := make(map[string]string)
	for k, v := range falcopayload.OutputFields {
		k := strings.Replace(k, ".", "_", -1)
		ret[k] = fmt.Sprintf("%v", v)
	}
	return ret
}
func traceIDFromTemplate(falcopayload types.FalcoPayload, config *types.Configuration) (string, string) {
	tplStr := config.OTLP.Traces.TraceIDFormat
	tpl := config.OTLP.Traces.TraceIDFormatTemplate
	outputFields := sanitizeOutputFields(falcopayload)
	if tpl == nil {
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
	// cluster, k8s.ns.name, k8s.pod.name, container.name, container.id
	traceIDStr, tplStr := traceIDFromTemplate(falcopayload, config)
	if traceIDStr == "" {
		// Generate a random 32 character string
		randomInt, err := rand.Int(rand.Reader, big.NewInt(
			100000000000000001,
		))
		if err != nil {
			return trace.TraceID{}, "", errors.New("Error generating random number")
		}
		traceIDStr = fmt.Sprintf("%032d", randomInt)
		tplStr = ""
	} else {
		hash := md5.Sum([]byte(traceIDStr))
		traceIDStr = hex.EncodeToString(hash[:])
	}
	traceID, err := trace.TraceIDFromHex(traceIDStr)
	return traceID, tplStr, err
}
