package outputs

import (
	"github.com/falcosecurity/falcosidekick/types"
)

// WebhookPost posts event to Slack
func (c *Client) WebhookPost(falcopayload types.FalcoPayload) {
	err := c.Post(falcopayload)
	if err != nil {
		c.Stats.Webhook.Add("error", 1)
	} else {
		c.Stats.Webhook.Add("ok", 1)
	}
	c.Stats.Webhook.Add("total", 1)
}
