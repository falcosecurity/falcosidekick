// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"

	cloudevents "github.com/cloudevents/sdk-go/v2"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

// CloudEventsSend produces a CloudEvent and sends to the CloudEvents consumers.
func (c *Client) CloudEventsSend(falcopayload types.FalcoPayload) {
	c.Stats.CloudEvents.Add(Total, 1)

	if c.CloudEventsClient == nil {
		client, err := cloudevents.NewClientHTTP()
		if err != nil {
			go c.CountMetric(Outputs, 1, []string{"output:cloudevents", "status:error"})
			c.Stats.CloudEvents.Add(Error, 1)
			c.PromStats.Outputs.With(map[string]string{"destination": "cloudevents", "status": Error}).Inc()
			c.OTLPMetrics.Outputs.With(attribute.String("destination", "cloudevents"),
				attribute.String("status", Error)).Inc()
			utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("NewDefaultClient : %v", err))
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
	event.SetExtension("eventsource", falcopayload.Source)

	if falcopayload.Hostname != "" {
		event.SetExtension(Hostname, falcopayload.Hostname)
	}

	// Set Extensions.
	for k, v := range c.Config.CloudEvents.Extensions {
		event.SetExtension(k, v)
	}

	if err := event.SetData(cloudevents.ApplicationJSON, falcopayload); err != nil {
		utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("failed to set data : %v", err))
	}

	if result := c.CloudEventsClient.Send(ctx, event); cloudevents.IsUndelivered(result) {
		go c.CountMetric(Outputs, 1, []string{"output:cloudevents", "status:error"})
		c.Stats.CloudEvents.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "cloudevents", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "cloudevents"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("%v", result))
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:cloudevents", "status:ok"})
	c.Stats.CloudEvents.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "cloudevents", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "cloudevents"),
		attribute.String("status", OK)).Inc()
	utils.Log(utils.InfoLvl, c.OutputType, "Send OK")
}
