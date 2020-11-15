package outputs

import (
	"github.com/falcosecurity/falcosidekick/types"
)

// WebhookPost posts event to Slack
func (c *Client) WebhookPost(falcopayload types.FalcoPayload) {
	err := c.Post(falcopayload)
	if err != nil {
		c.Stats.Webhook.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "webhook", "status": Error}).Inc()
	} else {
		c.Stats.Webhook.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "webhook", "status": OK}).Inc()
	}

	c.Stats.Webhook.Add(Total, 1)
}
