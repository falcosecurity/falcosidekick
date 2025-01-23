// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"go.opentelemetry.io/otel/attribute"
	"log"
	"net/http"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

// WebhookPost posts event to an URL
func (c *Client) WebhookPost(falcopayload types.FalcoPayload) {
	c.Stats.Webhook.Add(Total, 1)

	optfn := func(req *http.Request) {
		for i, j := range c.Config.Webhook.CustomHeaders {
			req.Header.Set(i, j)
		}
	}
	var err error
	if strings.ToUpper(c.Config.Webhook.Method) == HttpPut {
		err = c.Put(falcopayload, optfn)
	} else {
		err = c.Post(falcopayload, optfn)
	}

	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:webhook", "status:error"})
		c.Stats.Webhook.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "webhook", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "webhook"),
			attribute.String("status", Error)).Inc()
		log.Printf("[ERROR] : WebHook - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:webhook", "status:ok"})
	c.Stats.Webhook.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "webhook", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "webhook"),
		attribute.String("status", OK)).Inc()
}
