// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"

	"go.opentelemetry.io/otel/trace"
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

		client, _ := NewClient("OTLP", "http://localhost:4317", false, false, *initClientArgs)
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
