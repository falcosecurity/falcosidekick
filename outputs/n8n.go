// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"go.opentelemetry.io/otel/attribute"
	"log"
	"net/http"

	"github.com/falcosecurity/falcosidekick/types"
)

// N8NPost posts event to an URL
func (c *Client) N8NPost(falcopayload types.FalcoPayload) {
	c.Stats.N8N.Add(Total, 1)

	err := c.Post(falcopayload, func(req *http.Request) {
		if c.Config.N8N.User != "" && c.Config.N8N.Password != "" {
			req.SetBasicAuth(c.Config.N8N.User, c.Config.N8N.Password)
		}

		if c.Config.N8N.HeaderAuthName != "" && c.Config.N8N.HeaderAuthValue != "" {
			req.Header.Set(c.Config.N8N.HeaderAuthName, c.Config.N8N.HeaderAuthValue)
		}
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:n8n", "status:error"})
		c.Stats.N8N.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "n8n", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "n8n"),
			attribute.String("status", Error)).Inc()
		log.Printf("[ERROR] : N8N - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:n8n", "status:ok"})
	c.Stats.N8N.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "n8n", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "n8n"), attribute.String("status", OK)).Inc()
}
