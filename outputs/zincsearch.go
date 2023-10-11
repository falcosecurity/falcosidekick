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
	"fmt"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// ZincsearchPost posts event to Zincsearch
func (c *Client) ZincsearchPost(falcopayload types.FalcoPayload) {
	c.Stats.Zincsearch.Add(Total, 1)

	if c.Config.Zincsearch.Username != "" && c.Config.Zincsearch.Password != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.BasicAuth(c.Config.Zincsearch.Username, c.Config.Zincsearch.Password)
	}

	fmt.Println(c.EndpointURL)
	err := c.Post(falcopayload)
	if err != nil {
		c.setZincsearchErrorMetrics()
		log.Printf("[ERROR] : Zincsearch - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:zincsearch", "status:ok"})
	c.Stats.Zincsearch.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "zincsearch", "status": OK}).Inc()
}

// setZincsearchErrorMetrics set the error stats
func (c *Client) setZincsearchErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:zincsearch", "status:error"})
	c.Stats.Zincsearch.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "zincsearch", "status": Error}).Inc()
}
