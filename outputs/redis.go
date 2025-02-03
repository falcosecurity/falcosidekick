// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/outputs/otlpmetrics"
	"github.com/falcosecurity/falcosidekick/types"
)

func (c *Client) ReportError(err error) {
	go c.CountMetric(Outputs, 1, []string{"output:redis", "status:error"})
	c.Stats.Redis.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "redis", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "redis"),
		attribute.String("status", Error)).Inc()
	utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
}

func NewRedisClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	rClient := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Address,
		Password: config.Redis.Password,
		DB:       config.Redis.Database,
	})
	// Ping the Redis server to check if it's running
	pong, err := rClient.Ping(context.Background()).Result()
	if err != nil {
		utils.Log(utils.ErrorLvl, "Redis", fmt.Sprintf("Misconfiguration, cannot connect to the server: %v", err))
	}
	utils.Log(utils.InfoLvl, "Redis", fmt.Sprintf("Connected to redis server: %v", pong))

	return &Client{
		OutputType:      "Redis",
		Config:          config,
		RedisClient:     rClient,
		Stats:           stats,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

func (c *Client) RedisPost(falcopayload types.FalcoPayload) {
	c.Stats.Redis.Add(Total, 1)
	redisPayload, _ := json.Marshal(falcopayload)
	if strings.ToLower(c.Config.Redis.StorageType) == "hashmap" {
		_, err := c.RedisClient.HSet(context.Background(), c.Config.Redis.Key, falcopayload.UUID, redisPayload).Result()
		if err != nil {
			c.ReportError(err)
		}
	} else {
		_, err := c.RedisClient.RPush(context.Background(), c.Config.Redis.Key, redisPayload).Result()
		if err != nil {
			c.ReportError(err)
		}
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:redis", "status:ok"})
	c.Stats.Redis.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "redis", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "redis"), attribute.String("status", OK)).Inc()
}
