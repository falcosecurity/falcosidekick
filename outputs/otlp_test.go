package outputs

import (
	"context"
	"testing"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/samber/lo"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Need to mock three interfaces: TracerProvider, Tracer, Span
type (
	MockTracerProvider struct{}
	MockTracer         struct{}
	MockSpan           struct {
		name       string
		startOpts  []trace.SpanStartOption
		endOpts    []trace.SpanEndOption
		ctx        context.Context
		attributes map[attribute.Key]attribute.Value
	}
)

// TracerProvider interface {
func (*MockTracerProvider) Tracer(string, ...trace.TracerOption) trace.Tracer {
	return &MockTracer{}
}

// Tracer interface
func (*MockTracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return ctx, &MockSpan{
		ctx:        ctx,
		name:       name,
		startOpts:  opts,
		attributes: make(map[attribute.Key]attribute.Value),
	}
}

// Span interface
func (*MockSpan) AddEvent(string, ...trace.EventOption)            {}
func (*MockSpan) IsRecording() bool                                { return true }
func (*MockSpan) RecordError(err error, opts ...trace.EventOption) {}
func (*MockSpan) SetName(name string)                              {}
func (*MockSpan) SetStatus(code codes.Code, description string)    {}

func (*MockSpan) TracerProvider() trace.TracerProvider { return &MockTracerProvider{} }

func (m *MockSpan) End(opts ...trace.SpanEndOption) {
	m.endOpts = opts
}

func (m *MockSpan) SetAttributes(kv ...attribute.KeyValue) {
	for _, k := range kv {
		m.attributes[k.Key] = k.Value
	}
}

func (m *MockSpan) SpanContext() trace.SpanContext {
	return trace.SpanContextFromContext(m.ctx)
}

func MockGetTracerProvider() trace.TracerProvider {
	return &MockTracerProvider{}
}

func startOptIn(opt trace.SpanStartOption, opts []trace.SpanStartOption) bool {
	res := lo.Filter(opts, func(o trace.SpanStartOption, index int) bool {
		return o == opt
	})
	return len(res) == 1
}

func endOptIn(opt trace.SpanEndOption, opts []trace.SpanEndOption) bool {
	res := lo.Filter(opts, func(o trace.SpanEndOption, index int) bool {
		return o == opt
	})
	return len(res) == 1
}

func TestOtlpNewTrace(t *testing.T) {
	getTracerProvider = MockGetTracerProvider

	cases := []struct {
		msg            string
		fp             types.FalcoPayload
		config         types.Configuration
		expectedTplStr string
		expectedRandom bool
	}{
		{
			msg: "Kubernetes payload should use kubeTemplateStr for output fields",
			fp: types.FalcoPayload{
				Time: time.Now(),
				Rule: "Mock Rule#1",
				Tags: []string{"foo", "bar"},
				OutputFields: map[string]interface{}{
					"priority":           "info",
					"uuid":               uuid.New().String(),
					"source":             "falco",
					"cluster":            "my-cluster",
					"k8s.ns.name":        "my-ns",
					"k8s.pod.name":       "my-pod",
					"k8s.container.name": "my-container",
					"container.id":       "42",
					"hostname":           "myhost",
					"output":             "Hook this Mock!",
				},
			},
			config: types.Configuration{
				Debug: true,
				OTLP: types.OTLPOutputConfig{
					Traces: types.OTLPTraces{
						Duration: 1000,
					},
				},
			},
			expectedTplStr: kubeTemplateStr,
		},
		{
			msg: "Container-only payload should use containerTemplateStr for output fields",
			fp: types.FalcoPayload{
				Rule: "Mock Rule#2",
				OutputFields: map[string]interface{}{
					"container.id": "42",
				},
			},
			config: types.Configuration{
				Debug: true,
				OTLP: types.OTLPOutputConfig{
					Traces: types.OTLPTraces{
						Duration: 1000,
					},
				},
			},
			expectedTplStr: containerTemplateStr,
		},
		{
			msg: "TraceIDHash config must override defaults",
			fp: types.FalcoPayload{
				Rule: "Mock Rule#3",
				OutputFields: map[string]interface{}{
					"container.id": "42",
					"foo.bar":      "101",
				},
			},
			config: types.Configuration{
				Debug: true,
				OTLP: types.OTLPOutputConfig{
					Traces: types.OTLPTraces{
						Duration:    1000,
						TraceIDHash: "{{.foo_bar}}",
					},
				},
			},
			expectedTplStr: "{{.foo_bar}}",
		},
		{
			msg: "Verify traceID is random if TraceIDHash is empty",
			fp: types.FalcoPayload{
				Rule: "Mock Rule#4",
				OutputFields: map[string]interface{}{
					"container.id": "42",
				},
			},
			config: types.Configuration{
				Debug: true,
				OTLP: types.OTLPOutputConfig{
					Traces: types.OTLPTraces{
						Duration:    1000,
						TraceIDHash: "{{.foo_bar}}",
					},
				},
			},
			expectedTplStr: "{{.foo_bar}}",
			expectedRandom: true,
		},
	}
	for _, c := range cases {

		var err error
		client, _ := NewClient("OTLP", "http://localhost:4317", false, false, &c.config, nil, nil, nil, nil)
		// Unfortunately config.go:getConfig() is not exported, so replicate its OTLP initialization regarding TraceIDHash != ""
		if c.config.OTLP.Traces.TraceIDHash != "" {
			c.config.OTLP.Traces.TraceIDHashTemplate, err = template.New("").Option(templateOption).Parse(c.config.OTLP.Traces.TraceIDHash)
			require.Nil(t, err)

		}
		// Test newTrace()
		span := client.newTrace(c.fp)
		require.NotNil(t, span)

		// Verify SpanStartOption and SpanEndOption timestamps
		optStartTime := trace.WithTimestamp(c.fp.Time)
		optEndTime := trace.WithTimestamp(c.fp.Time.Add(time.Millisecond * time.Duration(c.config.OTLP.Traces.Duration)))
		require.Equal(t, startOptIn(optStartTime, (*span).(*MockSpan).startOpts), true, c.msg)
		require.Equal(t, endOptIn(optEndTime, (*span).(*MockSpan).endOpts), true, c.msg)

		// Verify span attributes
		require.Equal(t, attribute.StringSliceValue(c.fp.Tags), (*span).(*MockSpan).attributes[attribute.Key("tags")], c.msg)
		for k, v := range c.fp.OutputFields {
			require.Equal(t, attribute.StringValue(v.(string)), (*span).(*MockSpan).attributes[attribute.Key(k)], c.msg)
		}

		// Verify traceID
		traceID, templateStr, err := generateTraceID(c.fp, &c.config)
		require.Nil(t, err, c.msg)
		// Always generate a traceID (unless errored)
		require.NotEqual(t, "", traceID.String(), c.msg)
		// Verify expectedTplStr
		require.Equal(t, c.expectedTplStr, templateStr, c.msg)
		// Verify test case expecting a random traceID (i.e. when the template rendered to "")
		actualTraceID := (*span).(*MockSpan).SpanContext().TraceID()
		if c.expectedRandom {
			require.NotEqual(t, traceID, actualTraceID, c.msg)
		} else {
			require.Equal(t, traceID, actualTraceID, c.msg)
		}
	}
}
