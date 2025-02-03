// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewStatsdClient returns a new output.Client for sending metrics to StatsD.
func NewStatsdClient(outputType string, config *types.Configuration, stats *types.Statistics) (*statsd.Client, error) {
	statsdClient := new(statsd.Client)
	var err error
	var fwd string
	switch outputType {
	case "StatsD":
		statsdClient, err = statsd.New(config.Statsd.Forwarder, statsd.WithNamespace(config.Statsd.Namespace), statsd.WithTags(config.Statsd.Tags))
		fwd = config.Statsd.Forwarder
	case "DogStatsD":
		statsdClient, err = statsd.New(config.Dogstatsd.Forwarder, statsd.WithNamespace(config.Dogstatsd.Namespace), statsd.WithTags(config.Dogstatsd.Tags))
		fwd = config.Dogstatsd.Forwarder
	}
	if err != nil {
		utils.Log(utils.ErrorLvl, outputType, fmt.Sprintf("Can't configure client for %v - %v", fwd, err))
		return nil, err
	}

	return statsdClient, nil
}

// CountMetric sends metrics to StatsD/DogStatsD.
func (c *Client) CountMetric(metric string, value int64, tags []string) {
	if c.StatsdClient != nil {
		c.Stats.Statsd.Add("total", 1)
		t := ""
		if len(tags) != 0 {
			for _, i := range tags {
				s := strings.Split(i, ":")
				t += "." + strings.Replace(s[1], " ", "", -1)
			}
		}

		if err := c.StatsdClient.Count(metric+t, value, []string{}, 1); err != nil {
			c.Stats.Statsd.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "statsd", "status": Error}).Inc()
			c.OTLPMetrics.Outputs.With(attribute.String("destination", "statsd"),
				attribute.String("status", Error)).Inc()
			utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Unable to send metric (%v%v%v) : %v", c.Config.Statsd.Namespace, metric, t, err))

			return
		}

		c.Stats.Statsd.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "statsd", "status": OK}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "statsd"),
			attribute.String("status", OK)).Inc()
		utils.Log(utils.InfoLvl, c.OutputType, fmt.Sprintf("Send Metric OK (%v%v%v)", c.Config.Statsd.Namespace, metric, t))
	}

	if c.DogstatsdClient != nil {
		c.Stats.Dogstatsd.Add("total", 1)
		if err := c.DogstatsdClient.Count(metric, value, tags, 1); err != nil {
			c.Stats.Dogstatsd.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "dogstatsd", "status": Error}).Inc()
			c.OTLPMetrics.Outputs.With(attribute.String("destination", "dogstatsd"),
				attribute.String("status", Error)).Inc()
			utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("Send Metric Error (%v%v%v) : %v", c.Config.Statsd.Namespace, metric, tags, err))

			return
		}

		c.Stats.Dogstatsd.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "dogstatsd", "status": OK}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "dogstatsd"),
			attribute.String("status", OK)).Inc()
		utils.Log(utils.InfoLvl, c.OutputType, fmt.Sprintf("Send Metric OK (%v%v %v)", c.Config.Statsd.Namespace, metric, tags))
	}
}
