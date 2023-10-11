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
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

type lokiPayload struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values []lokiValue       `json:"values"`
}

type lokiValue = []string

// The Content-Type to send along with the request
const LokiContentType = "application/json"

func newLokiPayload(falcopayload types.FalcoPayload, config *types.Configuration) lokiPayload {
	s := make(map[string]string, 3+len(falcopayload.OutputFields)+len(config.Loki.ExtraLabelsList)+len(falcopayload.Tags))
	s["rule"] = falcopayload.Rule
	s["source"] = falcopayload.Source
	s["priority"] = falcopayload.Priority.String()

	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			for k := range config.Customfields {
				if i == k {
					s[strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(i, ".", ""), "]", ""), "[", "")] = strings.ReplaceAll(v, "\"", "")
				}
			}
			for _, k := range config.Loki.ExtraLabelsList {
				if i == k {
					s[strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(i, ".", ""), "]", ""), "[", "")] = strings.ReplaceAll(v, "\"", "")
				}
			}
		default:
			continue
		}
	}

	if falcopayload.Hostname != "" {
		s[Hostname] = falcopayload.Hostname
	}

	if len(falcopayload.Tags) != 0 {
		s["tags"] = strings.Join(falcopayload.Tags, ",")
	}

	return lokiPayload{Streams: []lokiStream{
		{
			Stream: s,
			Values: []lokiValue{[]string{fmt.Sprintf("%v", falcopayload.Time.UnixNano()), falcopayload.Output}},
		},
	}}
}

func (c *Client) configureTenant() {
	if c.Config.Loki.Tenant != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.AddHeader("X-Scope-OrgID", c.Config.Loki.Tenant)
	}
}

func (c *Client) configureAuth() {
	if c.Config.Loki.User != "" && c.Config.Loki.APIKey != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.BasicAuth(c.Config.Loki.User, c.Config.Loki.APIKey)
	}
}

func (c *Client) configureCustomHeaders() {
	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	for i, j := range c.Config.Loki.CustomHeaders {
		c.AddHeader(i, j)
	}
}

// LokiPost posts event to Loki
func (c *Client) LokiPost(falcopayload types.FalcoPayload) {
	c.Stats.Loki.Add(Total, 1)
	c.ContentType = LokiContentType

	c.configureTenant()
	c.configureAuth()
	c.configureCustomHeaders()

	err := c.Post(newLokiPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:loki", "status:error"})
		c.Stats.Loki.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "loki", "status": Error}).Inc()
		log.Printf("[ERROR] : Loki - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:loki", "status:ok"})
	c.Stats.Loki.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "loki", "status": OK}).Inc()
}
