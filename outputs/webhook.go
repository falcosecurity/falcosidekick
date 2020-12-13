package outputs

import (
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// WebhookPost posts event to Slack
func (c *Client) WebhookPost(falcopayload types.FalcoPayload) {
	c.Stats.Webhook.Add(Total, 1)

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:webhook", "status:error"})
		c.Stats.Webhook.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "webhook", "status": Error}).Inc()
		log.Printf("[ERROR] : WebHook - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:webhook", "status:ok"})
	c.Stats.Webhook.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "webhook", "status": OK}).Inc()
	log.Printf("[INFO] : WebHook - Publish OK\n")
}
