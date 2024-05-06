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
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

// WebhookPost posts event to an URL
func (c *Client) WebhookPost(falcopayload types.FalcoPayload) {
	c.Stats.Webhook.Add(Total, 1)

	if len(c.Config.Webhook.CustomHeaders) != 0 {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		for i, j := range c.Config.Webhook.CustomHeaders {
			c.AddHeader(i, j)
		}
	}
	var err error
	if strings.ToUpper(c.Config.Webhook.Method) == HttpPut {
		err = c.Put(falcopayload)
	} else {
		err = c.Post(falcopayload)
	}

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
}
