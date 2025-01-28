// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

type timescaledbPayload struct {
	SQL    string `json:"sql"`
	Values []any  `json:"values"`
}

func NewTimescaleDBClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

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
		utils.Log(utils.ErrorLvl, "TimescaleDB", err.Error())
		return nil, ErrClientCreation
	}

	return &Client{
		OutputType:        "TimescaleDB",
		Config:            config,
		TimescaleDBClient: connPool,
		Stats:             stats,
		PromStats:         promStats,
		OTLPMetrics:       otlpMetrics,
		StatsdClient:      statsdClient,
		DogstatsdClient:   dogstatsdClient,
	}, nil
}

func newTimescaleDBPayload(falcopayload types.FalcoPayload, config *types.Configuration) timescaledbPayload {
	vals := make(map[string]any, 7+len(config.Customfields)+len(config.Templatedfields))
	vals[Time] = falcopayload.Time
	vals[Rule] = falcopayload.Rule
	vals[Priority] = falcopayload.Priority.String()
	vals[Source] = falcopayload.Source
	vals["output"] = falcopayload.Output

	if len(falcopayload.Tags) != 0 {
		vals[Tags] = strings.Join(falcopayload.Tags, ",")
	}

	if falcopayload.Hostname != "" {
		vals[Hostname] = falcopayload.Hostname
	}

	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			for k := range config.Customfields {
				if i == k {
					vals[i] = strings.ReplaceAll(v, "\"", "")
				}
			}
			for k := range config.Templatedfields {
				if i == k {
					vals[i] = strings.ReplaceAll(v, "\"", "")
				}
			}
		default:
			continue
		}
	}

	i := 0
	retVals := make([]any, len(vals))
	var cols strings.Builder
	var args strings.Builder
	for k, v := range vals {
		cols.WriteString(k)
		fmt.Fprintf(&args, "$%d", i+1)
		if i < (len(vals) - 1) {
			cols.WriteString(",")
			args.WriteString(",")
		}

		str, isString := v.(string)
		if isString && (strings.ToLower(str) == "null") {
			retVals[i] = nil
		} else {
			retVals[i] = v
		}
		i++
	}

	sql := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		config.TimescaleDB.HypertableName,
		cols.String(),
		args.String())

	return timescaledbPayload{SQL: sql, Values: retVals}
}

func (c *Client) TimescaleDBPost(falcopayload types.FalcoPayload) {
	c.Stats.TimescaleDB.Add(Total, 1)

	var ctx = context.Background()
	tsdbPayload := newTimescaleDBPayload(falcopayload, c.Config)
	_, err := c.TimescaleDBClient.Exec(ctx, tsdbPayload.SQL, tsdbPayload.Values...)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:timescaledb", "status:error"})
		c.Stats.TimescaleDB.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "timescaledb", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "timescaledb"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:timescaledb", "status:ok"})
	c.Stats.TimescaleDB.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "timescaledb", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "timescaledb"),
		attribute.String("status", OK)).Inc()

	if c.Config.Debug {
		utils.Log(utils.DebugLvl, c.OutputType, fmt.Sprintf("payload : %v", tsdbPayload))
	}
}
