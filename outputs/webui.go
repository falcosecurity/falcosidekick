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

	"github.com/falcosecurity/falcosidekick/types"
)

type WebUIPayload struct {
	Event   types.FalcoPayload `json:"event"`
	Outputs []string           `json:"outputs"`
}

func newWebUIPayload(falcopayload types.FalcoPayload, config *types.Configuration) WebUIPayload {
	return WebUIPayload{
		Event:   falcopayload,
		Outputs: EnabledOutputs,
	}
}

// WebUIPost posts event to Slack
func (c *Client) WebUIPost(falcopayload types.FalcoPayload) {
	c.Stats.WebUI.Add(Total, 1)

	err := c.Post(newWebUIPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:webui", "status:error"})
		c.Stats.WebUI.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": Error}).Inc()
		log.Printf("[ERROR] : WebUI - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:webui", "status:ok"})
	c.Stats.WebUI.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": OK}).Inc()
}
