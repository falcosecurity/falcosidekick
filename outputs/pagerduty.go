package outputs

import (
	"fmt"
	"log"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/PagerDuty/go-pagerduty"
	"github.com/falcosecurity/falcosidekick/types"
)

// NewPagerdutyClient returns a new output.Client for accessing the Pagerduty API.
func NewPagerdutyClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	if len(config.Pagerduty.Assignee) > 0 && config.Pagerduty.EscalationPolicy != "" {
		return nil, fmt.Errorf("assignee and escalation policy cannot be both configured")
	}

	return &Client{
		OutputType:      "GCP",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
		PagerdutyClient: pagerduty.NewClient(config.Pagerduty.APIKey),
	}, nil
}

// PagerdutyPost posts incident to Pagerduty
func (c *Client) PagerdutyPost(falcopayload types.FalcoPayload) {
	c.Stats.Pagerduty.Add(Total, 1)

	// TODO: Implement pagerduty post
	err := c.Post(newDatadogPayload(falcopayload))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:error"})
		c.Stats.Pagerduty.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": Error}).Inc()
		log.Printf("[ERROR] : Pagerduty - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:ok"})
	c.Stats.Pagerduty.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": OK}).Inc()
	log.Printf("[INFO] : Pagerduty - Publish OK\n")
}
