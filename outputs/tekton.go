// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

// TektonPost posts event to EventListner
func (c *Client) TektonPost(falcopayload types.FalcoPayload) {
	c.Stats.Tekton.Add(Total, 1)

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:tekton", "status:error"})
		c.Stats.Tekton.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "tekton", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "tekton"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:tekton", "status:ok"})
	c.Stats.Tekton.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "tekton", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "tekton"), attribute.String("status", OK)).Inc()
}
