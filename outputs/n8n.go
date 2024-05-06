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

// N8NPost posts event to an URL
func (c *Client) N8NPost(falcopayload types.FalcoPayload) {
	c.Stats.N8N.Add(Total, 1)

	if c.Config.N8N.User != "" && c.Config.N8N.Password != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.BasicAuth(c.Config.N8N.User, c.Config.N8N.Password)
	}

	if c.Config.N8N.HeaderAuthName != "" && c.Config.N8N.HeaderAuthValue != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.AddHeader(c.Config.N8N.HeaderAuthName, c.Config.N8N.HeaderAuthValue)
	}

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:n8n", "status:error"})
		c.Stats.N8N.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "n8n", "status": Error}).Inc()
		log.Printf("[ERROR] : N8N - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:n8n", "status:ok"})
	c.Stats.N8N.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "n8n", "status": OK}).Inc()
}
