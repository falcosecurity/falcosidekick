package outputs

import (
	"github.com/falcosecurity/falcosidekick/types"
)

// RocketchatPost posts event to Rocketchat
func (c *Client) RocketchatPost(falcopayload types.FalcoPayload) {
	err := c.Post(newSlackPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Rocketchat.Add("error", 1)
	} else {
		c.Stats.Rocketchat.Add("ok", 1)
	}
	c.Stats.Rocketchat.Add("total", 1)
}
