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
	"encoding/base64"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// NodeRedPost posts event to Slack
func (c *Client) NodeRedPost(falcopayload types.FalcoPayload) {
	c.Stats.NodeRed.Add(Total, 1)

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	if c.Config.NodeRed.User != "" && c.Config.NodeRed.Password != "" {
		c.AddHeader("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Config.NodeRed.User+":"+c.Config.NodeRed.Password)))
	}

	if len(c.Config.NodeRed.CustomHeaders) != 0 {
		for i, j := range c.Config.NodeRed.CustomHeaders {
			c.AddHeader(i, j)
		}
	}

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:nodered", "status:error"})
		c.Stats.NodeRed.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "nodered", "status": Error}).Inc()
		log.Printf("[ERROR] : NodeRed - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:nodered", "status:ok"})
	c.Stats.NodeRed.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nodered", "status": OK}).Inc()
}
