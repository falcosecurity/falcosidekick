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
		OutputType:      "PagerDuty",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
		PagerdutyClient: pagerduty.NewClient(config.Pagerduty.APIKey),
	}, nil
}

// PagerdutyCreateIncident posts incident to Pagerduty
func (c *Client) PagerdutyCreateIncident(falcopayload types.FalcoPayload) {
	c.Stats.Pagerduty.Add(Total, 1)

	opts := &pagerduty.CreateIncidentOptions{
		Type:  "incident",
		Title: falcopayload.Output,
		Service: &pagerduty.APIReference{
			ID:   c.Config.Pagerduty.Service,
			Type: "service_reference",
		},
	}

	if len(c.Config.Pagerduty.Assignee) > 0 {
		assignments := make([]pagerduty.Assignee, len(c.Config.Pagerduty.Assignee))
		for i, a := range c.Config.Pagerduty.Assignee {
			assignments[i] = pagerduty.Assignee{
				Assignee: pagerduty.APIObject{
					ID:   a,
					Type: "user_reference",
				},
			}
		}
		opts.Assignments = assignments
	}

	if policy := c.Config.Pagerduty.EscalationPolicy; policy != "" {
		opts.EscalationPolicy = &pagerduty.APIReference{
			ID:   policy,
			Type: "escalation_policy_reference",
		}
	}

	if _, err := c.PagerdutyClient.CreateIncident("falcosidekick", opts); err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:error"})
		c.Stats.Pagerduty.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": Error}).Inc()
		log.Printf("[ERROR] : PagerDuty - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:ok"})
	c.Stats.Pagerduty.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": OK}).Inc()
	log.Printf("[INFO] : Pagerduty - Create Incident OK\n")
}
