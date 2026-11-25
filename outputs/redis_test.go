// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"expvar"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

func TestRedisPostDoesNotCountFailuresAsSuccess(t *testing.T) {
	for _, storageType := range []string{"list", "hashmap"} {
		t.Run(storageType, func(t *testing.T) {
			config := &types.Configuration{}
			config.Redis.Key = "falco"
			config.Redis.StorageType = storageType

			rClient := redis.NewClient(&redis.Options{
				Addr:        "127.0.0.1:1",
				DialTimeout: 100 * time.Millisecond,
				MaxRetries:  -1,
			})
			defer rClient.Close()

			promOutputs := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "redis_test_" + storageType, Help: "test"}, []string{"destination", "status"}) //nolint:goconst // label names of the production outputs CounterVec
			stats := &types.Statistics{Redis: expvar.NewMap("redis_test_" + storageType)}
			client := &Client{
				OutputType:  "Redis",
				Config:      config,
				RedisClient: rClient,
				Stats:       stats,
				PromStats:   &types.PromStatistics{Outputs: promOutputs},
				OTLPMetrics: &otlpmetrics.OTLPMetrics{Outputs: noopCounter{}},
			}

			client.RedisPost(types.FalcoPayload{UUID: "1234", Output: "test"})

			require.Equal(t, int64(1), getExpvarInt64(t, stats.Redis, Total))
			require.Equal(t, int64(1), getExpvarInt64(t, stats.Redis, Error))
			require.Equal(t, int64(0), getExpvarInt64(t, stats.Redis, OK))
			require.Equal(t, float64(1), testutil.ToFloat64(promOutputs.WithLabelValues("redis", Error)))
			require.Equal(t, float64(0), testutil.ToFloat64(promOutputs.WithLabelValues("redis", OK)))
		})
	}
}
