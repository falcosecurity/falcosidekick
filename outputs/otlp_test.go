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

	cases := []struct {
		fp         *types.FalcoPayload
		durationMs int64
		expectSpan bool
	}{
		{
			durationMs: 100,
			fp: &types.FalcoPayload{
				Time: time.Now(),
				Rule: "Mock Rule#1",
				OutputFields: map[string]interface{}{
					"priority":     "info",
					"uuid":         uuid.New().String(),
					"source":       "falco",
					"container.id": "42",
					"hostname":     "myhost",
					"output":       "Hook this Mock!",
				},
			},
			expectSpan: true,
		},
		{
			fp: &types.FalcoPayload{
				Rule: "Mock Rule#2",
				OutputFields: map[string]interface{}{
					"container.id": "not-Hex",
				},
			},
			expectSpan: false,
		},
	}
	for _, c := range cases {

		// Test newTrace()
		span := newTrace(*c.fp, c.durationMs)
		if !c.expectSpan {
			require.Nil(t, span)
			continue
		}

		// Verify SpanStartOption and SpanEndOption timestamps
		optStartTime := trace.WithTimestamp(c.fp.Time)
		optEndTime := trace.WithTimestamp(c.fp.Time.Add(time.Millisecond * time.Duration(c.durationMs)))
		require.Equal(t, startOptIn(optStartTime, (*span).(*MockSpan).startOpts), true, c.fp.Rule)
		require.Equal(t, endOptIn(optEndTime, (*span).(*MockSpan).endOpts), true, c.fp.Rule)

		// Verify span attributes
		for k, v := range c.fp.OutputFields {
			require.Equal(t, attribute.StringValue(v.(string)), (*span).(*MockSpan).attributes[attribute.Key(k)], c.fp.Rule)
		}

		// Verify traceID
		spanTraceID, _ := generateTraceID(c.fp.OutputFields["container.id"].(string))
		require.Equal(t, (*span).(*MockSpan).SpanContext().TraceID(), spanTraceID, c.fp.Rule)
	}
}
