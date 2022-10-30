package outputs

import (
	"context"
	"fmt"
	"log"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewTimescaleDBClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	ctx := context.Background()
	connStr := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s",
		config.TimescaleDB.User,
		config.TimescaleDB.Password,
		config.TimescaleDB.Host,
		config.TimescaleDB.Port,
		config.TimescaleDB.Database,
	)
	connPool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		log.Printf("[ERROR] : TimescaleDB - %v\n", err)
		return nil, ErrClientCreation
	}

	return &Client{
		OutputType:        "TimescaleDB",
		Config:            config,
		TimescaleDBClient: connPool,
		Stats:             stats,
		PromStats:         promStats,
		StatsdClient:      statsdClient,
		DogstatsdClient:   dogstatsdClient,
	}, nil
}

func (c *Client) TimescaleDBPost(falcopayload types.FalcoPayload) {
	c.Stats.TimescaleDB.Add(Total, 1)

	hypertable := c.Config.TimescaleDB.HypertableName
	queryInsertData := fmt.Sprintf("INSERT INTO %s (time, rule, priority, source, output) VALUES ($1, $2, $3, $4, $5)", hypertable)

	var ctx = context.Background()
	_, err := c.TimescaleDBClient.Exec(ctx, queryInsertData, falcopayload.Time, falcopayload.Rule, falcopayload.Priority.String(), falcopayload.Source, falcopayload.Output)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:timescaledb", "status:error"})
		c.Stats.TimescaleDB.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "timescaledb", "status": Error}).Inc()
		log.Printf("[ERROR] : TimescaleDB - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:timescaledb", "status:ok"})
	c.Stats.TimescaleDB.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "timescaledb", "status": OK}).Inc()
}
