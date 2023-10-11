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
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// OpenObservePost posts event to OpenObserve
func (c *Client) OpenObservePost(falcopayload types.FalcoPayload) {
	c.Stats.OpenObserve.Add(Total, 1)

	if c.Config.OpenObserve.Username != "" && c.Config.OpenObserve.Password != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.BasicAuth(c.Config.OpenObserve.Username, c.Config.OpenObserve.Password)
	}

	for i, j := range c.Config.OpenObserve.CustomHeaders {
		c.AddHeader(i, j)
	}

	if err := c.Post(falcopayload); err != nil {
		c.setOpenObserveErrorMetrics()
		log.Printf("[ERROR] : OpenObserve - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:openobserve", "status:ok"})
	c.Stats.OpenObserve.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "openobserve", "status": OK}).Inc()
}

// setOpenObserveErrorMetrics set the error stats
func (c *Client) setOpenObserveErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:openobserve", "status:error"})
	c.Stats.OpenObserve.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "openobserve", "status": Error}).Inc()
}
