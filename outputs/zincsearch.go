// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"log"
	"net/http"

	"github.com/falcosecurity/falcosidekick/types"
)

// ZincsearchPost posts event to Zincsearch
func (c *Client) ZincsearchPost(falcopayload types.FalcoPayload) {
	c.Stats.Zincsearch.Add(Total, 1)

	err := c.Post(falcopayload, func(req *http.Request) {
		if c.Config.Zincsearch.Username != "" && c.Config.Zincsearch.Password != "" {
			req.SetBasicAuth(c.Config.Zincsearch.Username, c.Config.Zincsearch.Password)
		}
	})
	if err != nil {
		c.setZincsearchErrorMetrics()
		log.Printf("[ERROR] : Zincsearch - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:zincsearch", "status:ok"})
	c.Stats.Zincsearch.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "zincsearch", "status": OK}).Inc()
}

// setZincsearchErrorMetrics set the error stats
func (c *Client) setZincsearchErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:zincsearch", "status:error"})
	c.Stats.Zincsearch.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "zincsearch", "status": Error}).Inc()
}
