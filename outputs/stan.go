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
	"encoding/json"
	"log"
	"strings"

	stan "github.com/nats-io/stan.go"

	"github.com/falcosecurity/falcosidekick/types"
)

// StanPublish publishes event to NATS Streaming
func (c *Client) StanPublish(falcopayload types.FalcoPayload) {
	c.Stats.Stan.Add(Total, 1)

	nc, err := stan.Connect(c.Config.Stan.ClusterID, c.Config.Stan.ClientID, stan.NatsURL(c.EndpointURL.String()))
	if err != nil {
		c.setStanErrorMetrics()
		log.Printf("[ERROR] : STAN - %v\n", err.Error())
		return
	}
	defer nc.Close()

	r := strings.Trim(slugRegularExpression.ReplaceAllString(strings.ToLower(falcopayload.Rule), "_"), "_")
	j, err := json.Marshal(falcopayload)
	if err != nil {
		c.setStanErrorMetrics()
		log.Printf("[ERROR] : STAN - %v\n", err.Error())
		return
	}

	err = nc.Publish("falco."+strings.ToLower(falcopayload.Priority.String())+"."+r, j)
	if err != nil {
		c.setStanErrorMetrics()
		log.Printf("[ERROR] : STAN - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:stan", "status:ok"})
	c.Stats.Stan.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "stan", "status": OK}).Inc()
	log.Printf("[INFO]  : STAN - Publish OK\n")
}

// setStanErrorMetrics set the error stats
func (c *Client) setStanErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:stan", "status:error"})
	c.Stats.Stan.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "stan", "status": Error}).Inc()
}
