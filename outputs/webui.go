// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

type WebUIPayload struct {
	Event   types.FalcoPayload `json:"event"`
	Outputs []string           `json:"outputs"`
}

func newWebUIPayload(falcopayload types.FalcoPayload, config *types.Configuration) WebUIPayload {
	return WebUIPayload{
		Event:   falcopayload,
		Outputs: EnabledOutputs,
	}
}

// WebUIPost posts event to Slack
func (c *Client) WebUIPost(falcopayload types.FalcoPayload) {
	c.Stats.WebUI.Add(Total, 1)

	err := c.Post(newWebUIPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:webui", "status:error"})
		c.Stats.WebUI.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": Error}).Inc()
		log.Printf("[ERROR] : WebUI - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:webui", "status:ok"})
	c.Stats.WebUI.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": OK}).Inc()
}
