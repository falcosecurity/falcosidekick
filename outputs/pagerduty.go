// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/PagerDuty/go-pagerduty"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	USEndpoint string = "https://events.pagerduty.com"
	EUEndpoint string = "https://events.eu.pagerduty.com"
)

// PagerdutyPost posts alert event to Pagerduty
func (c *Client) PagerdutyPost(falcopayload types.FalcoPayload) {
	c.Stats.Pagerduty.Add(Total, 1)

	event := createPagerdutyEvent(falcopayload, c.Config.Pagerduty)

	if strings.ToLower(c.Config.Pagerduty.Region) == "eu" {
		pagerduty.WithV2EventsAPIEndpoint(EUEndpoint)
	} else {
		pagerduty.WithV2EventsAPIEndpoint(USEndpoint)
	}

	if _, err := pagerduty.ManageEventWithContext(context.Background(), event); err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:error"})
		c.Stats.Pagerduty.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": Error}).Inc()
		log.Printf("[ERROR] : PagerDuty - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:ok"})
	c.Stats.Pagerduty.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": OK}).Inc()
	log.Printf("[INFO]  : Pagerduty - Create Incident OK\n")
}

func createPagerdutyEvent(falcopayload types.FalcoPayload, config types.PagerdutyConfig) pagerduty.V2Event {
	details := make(map[string]interface{}, len(falcopayload.OutputFields)+4)
	details["rule"] = falcopayload.Rule
	details["priority"] = falcopayload.Priority.String()
	details["source"] = falcopayload.Source
	if len(falcopayload.Hostname) != 0 {
		falcopayload.OutputFields[Hostname] = falcopayload.Hostname
	}
	if len(falcopayload.Tags) != 0 {
		sort.Strings(falcopayload.Tags)
		details["tags"] = strings.Join(falcopayload.Tags, ", ")
	}
	event := pagerduty.V2Event{
		RoutingKey: config.RoutingKey,
		Action:     "trigger",
		Payload: &pagerduty.V2Payload{
			Source:    "falco",
			Summary:   falcopayload.Output,
			Severity:  "critical",
			Timestamp: falcopayload.Time.Format(time.RFC3339),
			Details:   falcopayload.OutputFields,
		},
	}
	return event
}
