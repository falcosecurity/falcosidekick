// SPDX-License-Identifier: MIT OR Apache-2.0

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
		c.AddHeader(AuthorizationHeaderKey, Bearer+" "+c.Config.GCP.CloudRun.JWT)
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
