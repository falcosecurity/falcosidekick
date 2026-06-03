// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestOtlpNewTrace(t *testing.T) {
	// getTracerProvider = MockGetTracerProvider

	cases := []struct {
		msg            string
		fp             types.FalcoPayload
		config         types.Configuration
		expectedHash   string
		expectedRandom bool
		actualTraceID  trace.TraceID // save traceID for below cross-cases comparison
	}{
		{
			msg: "#1 Payload with Kubernetes namespace and pod names",
			fp: types.FalcoPayload{
				OutputFields: map[string]interface{}{
					"k8s.ns.name":  "my-ns",
					"k8s.pod.name": "my-pod-name",
					"container.id": "42",
					"evt.hostname": "localhost",
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
			expectedHash: "087e7ab4196a3c4801e3c23bc1406163",
		},
		{
			msg: "#2 Payload with container ID",
			fp: types.FalcoPayload{
				OutputFields: map[string]interface{}{
					"container.id": "42",
					"evt.hostname": "localhost",
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
			expectedHash: "088094c785ab1be95aa073305569c06b",
		},
		{
			msg: "#3 Payload with Hostname",
			fp: types.FalcoPayload{
				OutputFields: map[string]interface{}{
					"evt.hostname": "localhost",
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
			expectedHash: "b96c8fbfe005d268653aef8210412f0a",
		},
	}
	for idx, c := range cases {
		var err error
		config := &types.Configuration{}
		stats := &types.Statistics{}
		promStats := &types.PromStatistics{}

		initClientArgs := &types.InitClientArgs{
			Config:    config,
			Stats:     stats,
			PromStats: promStats,
		}

		client, _ := NewClient("OTLP", "http://localhost:4317", types.CommonConfig{}, *initClientArgs)
		// Test newTrace()
		span, err := client.newTrace(c.fp)
		require.Nil(t, err)
		require.NotNil(t, span)

		// Verify traceID
		// ~hack: to pass c.expectedRandom==true case, recreate fp.UUID as generateTraceID() derives from it
		traceID, err := generateTraceID(c.fp)
		require.Nil(t, err, c.msg)
		// Verify expectedHash
		require.Equal(t, c.expectedHash, traceID.String(), c.msg)

		// Save actualTraceID for 2nd pass comparison against other cases
		cases[idx].actualTraceID = c.actualTraceID
	}
	// 2nd pass to verify cross-case traceID comparisons (equality, difference)
}

// TestGenerateTraceIDWithNonStringFields ensures that non-string values in the
// output fields used to build the trace ID do not panic. These fields come from
// attacker-influenceable payloads, so a bare type assertion would panic and, since
// generateTraceID runs in its own goroutine, crash the whole process.
func TestGenerateTraceIDWithNonStringFields(t *testing.T) {
	cases := []struct {
		msg string
		fp  types.FalcoPayload
	}{
		{
			msg: "container.id as a JSON number",
			fp: types.FalcoPayload{
				OutputFields: map[string]interface{}{
					"container.id": json.Number("42"),
				},
			},
		},
		{
			msg: "k8s fields as bool and number",
			fp: types.FalcoPayload{
				OutputFields: map[string]interface{}{
					"k8s.ns.name":  true,
					"k8s.pod.name": json.Number("1"),
				},
			},
		},
		{
			msg: "evt.hostname as a nested object",
			fp: types.FalcoPayload{
				OutputFields: map[string]interface{}{
					"evt.hostname": map[string]interface{}{"nested": "value"},
				},
			},
		},
	}
	for _, c := range cases {
		require.NotPanics(t, func() {
			// No usable string field, so an error is expected, but never a panic.
			_, err := generateTraceID(c.fp)
			require.Error(t, err, c.msg)
		}, c.msg)
	}
}

// TestGenerateTraceIDFallsBackOnNonStringField ensures a non-string value for one
// field does not prevent a valid trace ID from being built from another field.
func TestGenerateTraceIDFallsBackOnNonStringField(t *testing.T) {
	fp := types.FalcoPayload{
		OutputFields: map[string]interface{}{
			"container.id": json.Number("42"), // non-string, must be ignored
			"evt.hostname": "localhost",       // valid, must be used
		},
	}
	require.NotPanics(t, func() {
		traceID, err := generateTraceID(fp)
		require.NoError(t, err)
		// Same hash as the "Payload with Hostname" case above.
		require.Equal(t, "b96c8fbfe005d268653aef8210412f0a", traceID.String())
	})
}
