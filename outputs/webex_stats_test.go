// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"expvar"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

func TestWebexPostUsesWebexStats(t *testing.T) {
	status := http.StatusOK
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	defer ts.Close()

	stats := &types.Statistics{
		Webex:   expvar.NewMap("webex_stats_test"),
		Webhook: expvar.NewMap("webex_stats_test_webhook"),
	}
	client, err := NewClient("Webex", ts.URL, types.CommonConfig{}, types.InitClientArgs{
		Config:      &types.Configuration{},
		Stats:       stats,
		PromStats:   &types.PromStatistics{Outputs: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "webex_stats_test", Help: "test"}, []string{"destination", "status"})}, //nolint:goconst // label names of the production outputs CounterVec
		OTLPMetrics: &otlpmetrics.OTLPMetrics{Outputs: noopCounter{}},
	})
	require.NoError(t, err)

	var falcoPayload types.FalcoPayload
	require.NoError(t, json.Unmarshal([]byte(falcoTestInput), &falcoPayload))

	client.WebexPost(falcoPayload)
	status = http.StatusBadRequest
	client.WebexPost(falcoPayload)

	require.Equal(t, int64(2), getExpvarInt64(t, stats.Webex, Total))
	require.Equal(t, int64(1), getExpvarInt64(t, stats.Webex, OK))
	require.Equal(t, int64(1), getExpvarInt64(t, stats.Webex, Error))
	require.Nil(t, stats.Webhook.Get(OK))
	require.Nil(t, stats.Webhook.Get(Error))
}
