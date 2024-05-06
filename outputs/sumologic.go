// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
	"log"
	"net/url"

	"github.com/falcosecurity/falcosidekick/types"
)

// SumoLogicPost posts event to SumoLogic
func (c *Client) SumoLogicPost(falcopayload types.FalcoPayload) {
	c.Stats.SumoLogic.Add(Total, 1)

	endpointURL, err := url.Parse(c.Config.SumoLogic.ReceiverURL)
	if err != nil {
		c.setSumoLogicErrorMetrics()
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		return
	}

	c.EndpointURL = endpointURL

	if c.Config.SumoLogic.SourceCategory != "" {
		c.AddHeader("X-Sumo-Category", c.Config.SumoLogic.SourceCategory)
	}

	if c.Config.SumoLogic.SourceHost != "" {
		c.AddHeader("X-Sumo-Host", c.Config.SumoLogic.SourceHost)
	}

	if c.Config.SumoLogic.Name != "" {
		c.AddHeader("X-Sumo-Name", c.Config.SumoLogic.Name)
	}

	err = c.Post(falcopayload)
	if err != nil {
		c.setSumoLogicErrorMetrics()
		log.Printf("[ERROR] : %x - %v\n", c.OutputType, err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:sumologic", "status:ok"})
	c.Stats.SumoLogic.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "sumologic", "status": OK}).Inc()
}

// setSumoLogicErrorMetrics set the error stats
func (c *Client) setSumoLogicErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:sumologic", "status:error"})
	c.Stats.SumoLogic.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "sumologic", "status": Error}).Inc()
}
