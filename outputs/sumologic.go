// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"go.opentelemetry.io/otel/attribute"
	"log"
	"net/http"
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

	err = c.Post(falcopayload,
		func(req *http.Request) {
			if c.Config.SumoLogic.SourceCategory != "" {
				req.Header.Set("X-Sumo-Category", c.Config.SumoLogic.SourceCategory)
			}

			if c.Config.SumoLogic.SourceHost != "" {
				req.Header.Set("X-Sumo-Host", c.Config.SumoLogic.SourceHost)
			}

			if c.Config.SumoLogic.Name != "" {
				req.Header.Set("X-Sumo-Name", c.Config.SumoLogic.Name)
			}
		},
		func(req *http.Request) {
			req.URL = endpointURL
		},
	)

	if err != nil {
		c.setSumoLogicErrorMetrics()
		log.Printf("[ERROR] : %x - %v\n", c.OutputType, err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:sumologic", "status:ok"})
	c.Stats.SumoLogic.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "sumologic", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "sumologic"),
		attribute.String("status", OK)).Inc()
}

// setSumoLogicErrorMetrics set the error stats
func (c *Client) setSumoLogicErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:sumologic", "status:error"})
	c.Stats.SumoLogic.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "sumologic", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "sumologic"),
		attribute.String("status", Error)).Inc()
}
