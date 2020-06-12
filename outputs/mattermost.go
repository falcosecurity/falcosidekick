package outputs

import (
	"github.com/falcosecurity/falcosidekick/types"
)

// MattermostPost posts event to Mattermost
func (c *Client) MattermostPost(falcopayload types.FalcoPayload) {
	err := c.Post(newSlackPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Mattermost.Add("error", 1)
	} else {
		c.Stats.Mattermost.Add("ok", 1)
	}
	c.Stats.Mattermost.Add("total", 1)
}
