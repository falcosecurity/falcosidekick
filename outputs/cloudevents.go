// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"log"

	cloudevents "github.com/cloudevents/sdk-go/v2"

	"github.com/falcosecurity/falcosidekick/types"
)

// CloudEventsSend produces a CloudEvent and sends to the CloudEvents consumers.
func (c *Client) CloudEventsSend(falcopayload types.FalcoPayload) {
	c.Stats.CloudEvents.Add(Total, 1)

	if c.CloudEventsClient == nil {
		client, err := cloudevents.NewClientHTTP()
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:cloudevents", "status:error"})
			log.Printf("[ERROR] : CloudEvents - NewDefaultClient : %v\n", err)
			return
		}
		c.CloudEventsClient = client
	}

	ctx := cloudevents.ContextWithTarget(context.Background(), c.EndpointURL.String())

	event := cloudevents.NewEvent()
	event.SetTime(falcopayload.Time)
	event.SetSource("https://falco.org")
	event.SetType("falco.rule.output.v1")
	event.SetExtension("priority", falcopayload.Priority.String())
	event.SetExtension("rule", falcopayload.Rule)
	event.SetExtension("event_source", falcopayload.Source)

	if falcopayload.Hostname != "" {
		event.SetExtension(Hostname, falcopayload.Hostname)
	}

	// Set Extensions.
	for k, v := range c.Config.CloudEvents.Extensions {
		event.SetExtension(k, v)
	}

	if err := event.SetData(cloudevents.ApplicationJSON, falcopayload); err != nil {
		log.Printf("[ERROR] : CloudEvents, failed to set data : %v\n", err)
	}

	if result := c.CloudEventsClient.Send(ctx, event); cloudevents.IsUndelivered(result) {
		go c.CountMetric(Outputs, 1, []string{"output:cloudevents", "status:error"})
		c.Stats.CloudEvents.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "cloudevents", "status": Error}).Inc()
		log.Printf("[ERROR] : CloudEvents - %v\n", result)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:cloudevents", "status:ok"})
	c.Stats.CloudEvents.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "cloudevents", "status": OK}).Inc()
	log.Printf("[INFO]  : CloudEvents - Send OK\n")
}
