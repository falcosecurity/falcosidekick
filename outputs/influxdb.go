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

type influxdbPayload string

func newInfluxdbPayload(falcopayload types.FalcoPayload, config *types.Configuration) influxdbPayload {
	s := "events,rule=" + strings.Replace(falcopayload.Rule, " ", "_", -1) + ",priority=" + falcopayload.Priority.String() + ",source=" + falcopayload.Source

	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			s += "," + i + "=" + strings.Replace(v, " ", "_", -1)
		default:
			continue
		}
	}

	if falcopayload.Hostname != "" {
		s += "," + Hostname + "=" + falcopayload.Hostname
	}

	if len(falcopayload.Tags) != 0 {
		s += ",tags=" + strings.Join(falcopayload.Tags, "_")
	}

	s += " value=\"" + falcopayload.Output + "\""

	return influxdbPayload(s)
}

// InfluxdbPost posts event to InfluxDB
func (c *Client) InfluxdbPost(falcopayload types.FalcoPayload) {
	c.Stats.Influxdb.Add(Total, 1)

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	c.AddHeader("Accept", "application/json")

	if c.Config.Influxdb.Token != "" {
		c.AddHeader("Authorization", "Token "+c.Config.Influxdb.Token)
	}

	err := c.Post(newInfluxdbPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:influxdb", "status:error"})
		c.Stats.Influxdb.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "influxdb", "status": Error}).Inc()
		log.Printf("[ERROR] : InfluxDB - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:influxdb", "status:ok"})
	c.Stats.Influxdb.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "influxdb", "status": OK}).Inc()
}
