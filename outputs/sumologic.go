// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"log"
	"net/url"

	"github.com/falcosecurity/falcosidekick/types"
)

// SumoLogicPost posts event to SumoLogic
func (c *Client) SumoLogicPost(falcopayload types.FalcoPayload) {
	c.Stats.SumoLogic.Add(Total, 1)

	endpointURL, err := url.Parse(c.Config.SumoLogic.ReceiverURL)
	if err != nil {
		c.setSumoLogicErrorMetrics()
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		return
	}

	c.EndpointURL = endpointURL

	if c.Config.SumoLogic.SourceCategory != "" {
		c.AddHeader("X-Sumo-Category", c.Config.SumoLogic.SourceCategory)
	}

	if c.Config.SumoLogic.SourceHost != "" {
		c.AddHeader("X-Sumo-Host", c.Config.SumoLogic.SourceHost)
	}

	if c.Config.SumoLogic.Name != "" {
		c.AddHeader("X-Sumo-Name", c.Config.SumoLogic.Name)
	}

	err = c.Post(falcopayload)
	if err != nil {
		c.setSumoLogicErrorMetrics()
		log.Printf("[ERROR] : %x - %v\n", c.OutputType, err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:sumologic", "status:ok"})
	c.Stats.SumoLogic.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "sumologic", "status": OK}).Inc()
}

// setSumoLogicErrorMetrics set the error stats
func (c *Client) setSumoLogicErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:sumologic", "status:error"})
	c.Stats.SumoLogic.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "sumologic", "status": Error}).Inc()
}
