// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DataDog/datadog-go/statsd"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/outputs/otlpmetrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewRabbitmqClient returns a new output.Client for accessing the RabbitmMQ API.
func NewRabbitmqClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	var channel *amqp.Channel
	if config.Rabbitmq.URL != "" && config.Rabbitmq.Queue != "" {
		conn, err := amqp.Dial(config.Rabbitmq.URL)
		if err != nil {
			utils.Log(utils.ErrorLvl, "Rabbitmq", "Error while connecting rabbitmq")
			return nil, errors.New("error while connecting Rabbitmq")
		}
		ch, err := conn.Channel()
		if err != nil {
			utils.Log(utils.ErrorLvl, "Rabbitmq", "Error while creating rabbitmq channel")
			return nil, errors.New("error while creating rabbitmq channel")
		}
		channel = ch
	}

	return &Client{
		OutputType:      "RabbitMQ",
		Config:          config,
		RabbitmqClient:  channel,
		Stats:           stats,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// Publish sends a message to a Rabbitmq
func (c *Client) Publish(falcopayload types.FalcoPayload) {
	c.Stats.Rabbitmq.Add(Total, 1)

	payload, _ := json.Marshal(falcopayload)

	err := c.RabbitmqClient.Publish("", c.Config.Rabbitmq.Queue, false, false, amqp.Publishing{
		ContentType: "text/plain",
		Body:        payload,
	})

	if err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Error while publishing message: %v", err))
		c.Stats.Rabbitmq.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:rabbitmq", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "rabbitmq", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "rabbitmq"),
			attribute.String("status", Error)).Inc()

		return
	}

	utils.Log(utils.InfoLvl, c.OutputType, "Message published OK")
	c.Stats.Rabbitmq.Add(OK, 1)
	go c.CountMetric("outputs", 1, []string{"output:rabbitmq", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "rabbitmq", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "rabbitmq"),
		attribute.String("status", OK)).Inc()
}
