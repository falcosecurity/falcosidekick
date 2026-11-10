// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"expvar"
	"testing"

	"github.com/embano1/memlog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

func TestEnqueueSecurityLakeErrorMetricDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ml, err := memlog.New(ctx)
	require.NoError(t, err)
	cancel()

	config := &types.Configuration{}
	config.AWS.SecurityLake.Ctx = ctx
	config.AWS.SecurityLake.Memlog = ml

	promOutputs := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "awssecuritylake_enqueue_test", Help: "test"}, []string{"destination", "status"}) //nolint:goconst // label names of the production outputs CounterVec
	client := &Client{
		OutputType:  "AWS",
		Config:      config,
		Stats:       &types.Statistics{AWSSecurityLake: expvar.NewMap("awssecuritylake_enqueue_test")},
		PromStats:   &types.PromStatistics{Outputs: promOutputs},
		OTLPMetrics: &otlpmetrics.OTLPMetrics{Outputs: noopCounter{}},
	}

	client.EnqueueSecurityLake(types.FalcoPayload{Output: "test"})

	require.Equal(t, int64(1), getExpvarInt64(t, client.Stats.AWSSecurityLake, Error))
	require.Equal(t, float64(1), testutil.ToFloat64(promOutputs.WithLabelValues("awssecuritylake", Error)))
	require.Equal(t, 1, testutil.CollectAndCount(promOutputs))
}
