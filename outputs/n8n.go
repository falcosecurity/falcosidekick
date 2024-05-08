// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// N8NPost posts event to an URL
func (c *Client) N8NPost(falcopayload types.FalcoPayload) {
	c.Stats.N8N.Add(Total, 1)

	if c.Config.N8N.User != "" && c.Config.N8N.Password != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.BasicAuth(c.Config.N8N.User, c.Config.N8N.Password)
	}

	if c.Config.N8N.HeaderAuthName != "" && c.Config.N8N.HeaderAuthValue != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.AddHeader(c.Config.N8N.HeaderAuthName, c.Config.N8N.HeaderAuthValue)
	}

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:n8n", "status:error"})
		c.Stats.N8N.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "n8n", "status": Error}).Inc()
		log.Printf("[ERROR] : N8N - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:n8n", "status:ok"})
	c.Stats.N8N.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "n8n", "status": OK}).Inc()
}
