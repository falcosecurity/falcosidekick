package outputs

import (
	"context"
	"testing"
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
type MockTracerProvider struct{}
type MockTracer struct{}
type MockSpan struct {
	name       string
	startTime  time.Time
	startOpts  []trace.SpanStartOption
	endOpts    []trace.SpanEndOption
	ctx        context.Context
	attributes map[attribute.Key]attribute.Value
}

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

	config := &types.Configuration{
		Debug: true,
		OTLP: types.OTLPOutputConfig{
			Traces: types.OTLPTraces{
				Duration: 100,
			},
		},
	}
	cases := []struct {
		fp             types.FalcoPayload
		expectedTplStr string
	}{
		{
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
			expectedTplStr: kubeTemplateStr,
		},
		{
			fp: types.FalcoPayload{
				Rule: "Mock Rule#2",
				OutputFields: map[string]interface{}{
					"container.id": "42",
				},
			},
			expectedTplStr: containerTemplateStr,
		},
	}
	for _, c := range cases {

		// Test newTrace()
		span := newTrace(c.fp, config)
		require.NotNil(t, span)

		// Verify SpanStartOption and SpanEndOption timestamps
		msg := c.fp.Rule
		optStartTime := trace.WithTimestamp(c.fp.Time)
		optEndTime := trace.WithTimestamp(c.fp.Time.Add(time.Millisecond * time.Duration(config.OTLP.Traces.Duration)))
		require.Equal(t, startOptIn(optStartTime, (*span).(*MockSpan).startOpts), true, msg)
		require.Equal(t, endOptIn(optEndTime, (*span).(*MockSpan).endOpts), true, msg)

		// Verify span attributes
		require.Equal(t, attribute.StringSliceValue(c.fp.Tags), (*span).(*MockSpan).attributes[attribute.Key("tags")], msg)
		for k, v := range c.fp.OutputFields {
			require.Equal(t, attribute.StringValue(v.(string)), (*span).(*MockSpan).attributes[attribute.Key(k)], msg)
		}

		// Verify traceID
		spanTraceID, templateStr, err := generateTraceID(c.fp, config)
		require.Nil(t, err, msg)
		require.Equal(t, c.expectedTplStr, templateStr, c.fp.Rule, msg)
		require.NotEqual(t, "", spanTraceID.String(), msg)
		require.Equal(t, spanTraceID, (*span).(*MockSpan).SpanContext().TraceID(), msg)
	}
}
