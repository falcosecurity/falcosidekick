// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package outputs

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/samber/lo"

	"go.opentelemetry.io/otel/trace"
)

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
		client, _ := NewClient("OTLP", "http://localhost:4317", false, false, &c.config, nil, nil, nil, nil)
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
