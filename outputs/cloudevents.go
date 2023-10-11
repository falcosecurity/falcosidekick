// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
