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

// TektonPost posts event to EventListner
func (c *Client) TektonPost(falcopayload types.FalcoPayload) {
	c.Stats.Tekton.Add(Total, 1)

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:tekton", "status:error"})
		c.Stats.Tekton.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "tekton", "status": Error}).Inc()
		log.Printf("[ERROR] : Tekton - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:tekton", "status:ok"})
	c.Stats.Tekton.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "tekton", "status": OK}).Inc()
}
