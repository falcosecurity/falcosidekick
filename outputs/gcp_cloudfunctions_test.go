// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"expvar"
	"testing"

	gcpfunctions "cloud.google.com/go/functions/apiv1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

func TestGCPCallCloudFunctionErrorUsesCloudFunctionsStats(t *testing.T) {
	fnClient, err := gcpfunctions.NewCloudFunctionsClient(context.Background(),
		option.WithEndpoint("127.0.0.1:1"),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	require.NoError(t, err)
	defer fnClient.Close()

	config := &types.Configuration{}
	config.GCP.CloudFunctions.Name = "projects/p/locations/l/functions/f"

	stats := &types.Statistics{
		GCPCloudFunctions: expvar.NewMap("gcp_cloudfunctions_error_test"),
		GCPPubSub:         expvar.NewMap("gcp_cloudfunctions_error_test_pubsub"),
	}
	promOutputs := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gcp_cloudfunctions_error_test", Help: "test"}, []string{"destination", "status"}) //nolint:goconst // label names of the production outputs CounterVec
	client := &Client{
		OutputType:              "GCP",
		Config:                  config,
		Stats:                   stats,
		PromStats:               &types.PromStatistics{Outputs: promOutputs},
		OTLPMetrics:             &otlpmetrics.OTLPMetrics{Outputs: noopCounter{}},
		GCPCloudFunctionsClient: fnClient,
	}

	client.GCPCallCloudFunction(types.FalcoPayload{Output: "test"})

	require.Equal(t, int64(1), getExpvarInt64(t, stats.GCPCloudFunctions, Total))
	require.Equal(t, int64(1), getExpvarInt64(t, stats.GCPCloudFunctions, Error))
	require.Equal(t, int64(0), getExpvarInt64(t, stats.GCPPubSub, Error))
	require.Equal(t, float64(1), testutil.ToFloat64(promOutputs.WithLabelValues("gcpcloudfunctions", Error)))
}
