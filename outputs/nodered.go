// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"go.opentelemetry.io/otel/attribute"
	"log"
	"net/http"

	"github.com/falcosecurity/falcosidekick/types"
)

// NodeRedPost posts event to Slack
func (c *Client) NodeRedPost(falcopayload types.FalcoPayload) {
	c.Stats.NodeRed.Add(Total, 1)

	err := c.Post(falcopayload, func(req *http.Request) {
		if c.Config.NodeRed.User != "" && c.Config.NodeRed.Password != "" {
			req.SetBasicAuth(c.Config.NodeRed.User, c.Config.NodeRed.Password)
		}

		for i, j := range c.Config.NodeRed.CustomHeaders {
			req.Header.Set(i, j)
		}
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:nodered", "status:error"})
		c.Stats.NodeRed.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "nodered", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "nodered"),
			attribute.String("status", Error)).Inc()
		log.Printf("[ERROR] : NodeRed - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:nodered", "status:ok"})
	c.Stats.NodeRed.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nodered", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "nodered"),
		attribute.String("status", OK)).Inc()
}
