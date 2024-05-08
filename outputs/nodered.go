// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/base64"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// NodeRedPost posts event to Slack
func (c *Client) NodeRedPost(falcopayload types.FalcoPayload) {
	c.Stats.NodeRed.Add(Total, 1)

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	if c.Config.NodeRed.User != "" && c.Config.NodeRed.Password != "" {
		c.AddHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Config.NodeRed.User+":"+c.Config.NodeRed.Password)))
	}

	if len(c.Config.NodeRed.CustomHeaders) != 0 {
		for i, j := range c.Config.NodeRed.CustomHeaders {
			c.AddHeader(i, j)
		}
	}

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:nodered", "status:error"})
		c.Stats.NodeRed.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "nodered", "status": Error}).Inc()
		log.Printf("[ERROR] : NodeRed - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:nodered", "status:ok"})
	c.Stats.NodeRed.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nodered", "status": OK}).Inc()
}
