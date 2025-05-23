// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"crypto/tls"
	"fmt"

	"github.com/DataDog/datadog-go/statsd"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewMQTTClient returns a new output.Client for accessing Kubernetes.
func NewMQTTClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics,
	otlpMetrics *otlpmetrics.OTLPMetrics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	options := mqtt.NewClientOptions()
	options.AddBroker(config.MQTT.Broker)
	options.SetClientID("falcosidekick-" + uuid.NewString()[:6])
	if config.MQTT.User != "" && config.MQTT.Password != "" {
		options.Username = config.MQTT.User
		options.Password = config.MQTT.Password
	}
	if !config.MQTT.CheckCert {
		options.TLSConfig = &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 This is only set as a result of explicit configuration
		}
	}
	options.OnConnectionLost = func(client mqtt.Client, err error) {
		utils.Log(utils.ErrorLvl, "MQTT", fmt.Sprintf("Connection lost: %v", err))
	}

	client := mqtt.NewClient(options)

	return &Client{
		OutputType:      MQTT,
		Config:          config,
		MQTTClient:      client,
		Stats:           stats,
		PromStats:       promStats,
		OTLPMetrics:     otlpMetrics,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// MQTTPublish .
func (c *Client) MQTTPublish(falcopayload types.FalcoPayload) {
	c.Stats.MQTT.Add(Total, 1)

	t := c.MQTTClient.Connect()
	t.Wait()
	if err := t.Error(); err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:mqtt", "status:error"})
		c.Stats.MQTT.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "mqtt", "status": err.Error()}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "mqtt"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}
	defer c.MQTTClient.Disconnect(100)
	if err := c.MQTTClient.Publish(c.Config.MQTT.Topic, byte(c.Config.MQTT.QOS), c.Config.MQTT.Retained, falcopayload.String()).Error(); err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:mqtt", "status:error"})
		c.Stats.MQTT.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "mqtt", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "mqtt"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	utils.Log(utils.InfoLvl, c.OutputType, "Message published")
	go c.CountMetric(Outputs, 1, []string{"output:mqtt", "status:ok"})
	c.Stats.MQTT.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "mqtt", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "mqtt"), attribute.String("status", OK)).Inc()
}
