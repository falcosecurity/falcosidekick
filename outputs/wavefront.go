// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"

	wavefront "github.com/wavefronthq/wavefront-sdk-go/senders"
)

// NewWavefrontClient returns a new output.Client for accessing the Wavefront API.
func NewWavefrontClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {

	var sender wavefront.Sender
	var err error

	batchSize := config.Wavefront.BatchSize
	if batchSize < 1 {
		batchSize = 10000 // Defaults to 10000
	}

	flushInterval := config.Wavefront.FlushIntervalSeconds
	if flushInterval < 1 {
		flushInterval = 1 // Defaults to 1s
	}

	switch config.Wavefront.EndpointType {
	case "direct":
		server := fmt.Sprintf("https://%s@%s", config.Wavefront.EndpointToken, config.Wavefront.EndpointHost)
		sender, err = wavefront.NewSender(
			server,
			wavefront.BatchSize(batchSize),
			wavefront.FlushIntervalSeconds(flushInterval),
		)
	case "proxy":
		sender, err = wavefront.NewSender(
			config.Wavefront.EndpointHost,
			wavefront.MetricsPort(config.Wavefront.EndpointMetricPort),
		)
	default:
		return nil, fmt.Errorf("failed to configure wavefront sender: invalid type %s", config.Wavefront.EndpointType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to configure wavefront %s sender: %s", config.Wavefront.EndpointType, err)
	}

	return &Client{
		OutputType:      "Wavefront",
		Config:          config,
		WavefrontSender: &sender,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}, nil
}

// WavefrontPost sends metrics to WaveFront.
func (c *Client) WavefrontPost(falcopayload types.FalcoPayload) {

	tags := make(map[string]string)
	tags["severity"] = falcopayload.Priority.String()
	tags["rule"] = falcopayload.Rule
	tags["source"] = falcopayload.Source

	if falcopayload.Hostname != "" {
		tags[Hostname] = falcopayload.Hostname
	}

	for tag, value := range falcopayload.OutputFields {
		switch v := value.(type) {
		case string:
			tags[tag] = v
		default:
			continue
		}
	}

	if len(falcopayload.Tags) != 0 {
		tags["tags"] = strings.Join(falcopayload.Tags, ", ")

	}

	c.Stats.Wavefront.Add(Total, 1)

	if c.WavefrontSender != nil {
		sender := *c.WavefrontSender
		// TODO: configurable metric name
		if err := sender.SendMetric(c.Config.Wavefront.MetricName, 1, falcopayload.Time.UnixNano(), "falco-exporter", tags); err != nil {
			c.Stats.Wavefront.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "wavefront", "status": Error}).Inc()
			log.Printf("[ERROR] : Wavefront - Unable to send event %s: %s\n", falcopayload.Rule, err)
			return
		}
		if err := sender.Flush(); err != nil {
			c.Stats.Wavefront.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "wavefront", "status": Error}).Inc()
			log.Printf("[ERROR] : Wavefront - Unable to flush event %s: %s\n", falcopayload.Rule, err)
			return
		}
		c.Stats.Wavefront.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "wavefront", "status": OK}).Inc()
		log.Printf("[INFO]  : Wavefront - Send Event OK %s\n", falcopayload.Rule)
	}
}
