// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
	"encoding/json"
	"errors"
	"log"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	amqp "github.com/rabbitmq/amqp091-go"
)

// NewRabbitmqClient returns a new output.Client for accessing the RabbitmMQ API.
func NewRabbitmqClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	var channel *amqp.Channel
	if config.Rabbitmq.URL != "" && config.Rabbitmq.Queue != "" {
		conn, err := amqp.Dial(config.Rabbitmq.URL)
		if err != nil {
			log.Printf("[ERROR] : Rabbitmq - %v\n", "Error while connecting rabbitmq")
			return nil, errors.New("error while connecting Rabbitmq")
		}
		ch, err := conn.Channel()
		if err != nil {
			log.Printf("[ERROR] : Rabbitmq Channel - %v\n", "Error while creating rabbitmq channel")
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
		log.Printf("[ERROR] : RabbitMQ - %v - %v\n", "Error while publishing message", err.Error())
		c.Stats.Rabbitmq.Add(Error, 1)
		go c.CountMetric("outputs", 1, []string{"output:rabbitmq", "status:error"})
		c.PromStats.Outputs.With(map[string]string{"destination": "rabbitmq", "status": Error}).Inc()

		return
	}

	log.Printf("[INFO]  : RabbitMQ - Send to message OK \n")
	c.Stats.Rabbitmq.Add(OK, 1)
	go c.CountMetric("outputs", 1, []string{"output:rabbitmq", "status:ok"})
	c.PromStats.Outputs.With(map[string]string{"destination": "rabbitmq", "status": OK}).Inc()
}
