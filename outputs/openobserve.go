// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

// OpenObservePost posts event to OpenObserve
func (c *Client) OpenObservePost(falcopayload types.FalcoPayload) {
	c.Stats.OpenObserve.Add(Total, 1)

	err := c.Post(falcopayload, func(req *http.Request) {
		if c.Config.OpenObserve.Username != "" && c.Config.OpenObserve.Password != "" {
			req.SetBasicAuth(c.Config.OpenObserve.Username, c.Config.OpenObserve.Password)
		}

		for i, j := range c.Config.OpenObserve.CustomHeaders {
			req.Header.Set(i, j)
		}
	})
	if err != nil {
		c.setOpenObserveErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:openobserve", "status:ok"})
	c.Stats.OpenObserve.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "openobserve", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "openobserve"),
		attribute.String("status", OK)).Inc()
}

// setOpenObserveErrorMetrics set the error stats
func (c *Client) setOpenObserveErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:openobserve", "status:error"})
	c.Stats.OpenObserve.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "openobserve", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "openobserve"),
		attribute.String("status", Error)).Inc()
}
