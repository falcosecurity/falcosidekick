// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
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
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:zincsearch", "status:ok"})
	c.Stats.Zincsearch.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "zincsearch", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "zincsearch"),
		attribute.String("status", OK)).Inc()
}

// setZincsearchErrorMetrics set the error stats
func (c *Client) setZincsearchErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:zincsearch", "status:error"})
	c.Stats.Zincsearch.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "zincsearch", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "zincsearch"),
		attribute.String("status", Error)).Inc()
}
