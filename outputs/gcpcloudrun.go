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

// CloudRunFunctionPost call Cloud Function
func (c *Client) CloudRunFunctionPost(falcopayload types.FalcoPayload) {
	c.Stats.GCPCloudRun.Add(Total, 1)

	if c.Config.GCP.CloudRun.JWT != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.AddHeader(AuthorizationHeaderKey, "Bearer "+c.Config.GCP.CloudRun.JWT)
	}

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:gcpcloudrun", "status:error"})
		c.Stats.GCPCloudRun.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "gcpcloudrun", "status": Error}).Inc()
		log.Printf("[ERROR] : GCPCloudRun - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:gcpcloudrun", "status:ok"})
	c.Stats.GCPCloudRun.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "gcpcloudrun", "status": OK}).Inc()
}
