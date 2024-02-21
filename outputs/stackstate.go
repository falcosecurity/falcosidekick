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

const (
	// StackStateEndpoint is the path of StackState's event API
	StackStateEndpoint string = "/receiver/stsAgent/intake"
)

type stackstatePayload struct {
	CollectionTimestamp int64           `json:"collection_timestamp"` // Epoch timestamp in seconds
	InternalHostname    string          `json:"internalHostname"`     // The hostname sending the data
	Events              events          `json:"events"`               // The events to send to StackState
	Metrics             []metrics       `json:"metrics"`              // Required present, but can be empty
	ServiceChecks       []serviceChecks `json:"service_checks"`       // Required present, but can be empty
	Health              []health        `json:"health"`               // Required present, but can be empty
	Topologies          []topology      `json:"topologies"`           // Required present, but can be empty
}

type events map[string][]eventPayload

type eventPayload struct {
	Context        eventContext `json:"context"`
	EventType      string       `json:"event_type"`
	Title          string       `json:"msg_title"`
	Text           string       `json:"msg_text"`
	SourceTypeName string       `json:"source_type_name"`
	Tags           []string     `json:"tags"`
	Timestamp      int64        `json:"timestamp"`
}

type eventContext struct {
	Category           string            `json:"category"`            // The event category. Can be Activities, Alerts, Anomalies, Changes or Others.
	Data               map[string]string `json:"data"`                // Optional. A list of key/value details about the event, for example a configuration version.
	ElementIdentifiers []string          `json:"element_identifiers"` // The identifiers for the topology element(s) the event relates to. These are used to bind the event to a topology element or elements.
	Source             string            `json:"source"`              // The name of the system from which the event originates, for example AWS, Kubernetes or JIRA.
	SourceLinks        []eventLink       `json:"source_links"`
}

type eventLink struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type metrics struct{}

type serviceChecks struct{}

type health struct{}

type topology struct{}

func emptyPayload() *stackstatePayload {
	return &stackstatePayload{
		Events:        events{},
		Metrics:       []metrics{},
		ServiceChecks: []serviceChecks{},
		Health:        []health{},
		Topologies:    []topology{},
	}
}

func newStackStatePayload(falcopayload types.FalcoPayload, stackstateConfig types.StackStateOutputConfig) stackstatePayload {
	var stsPayload *stackstatePayload = emptyPayload()
	var stsEvent eventPayload
	var stsContext eventContext

	stsEvent.Tags = buildTags(falcopayload)
	stsEvent.Timestamp = falcopayload.Time.Unix()
	stsEvent.Title = falcopayload.Rule
	stsEvent.Text = falcopayload.Output
	stsEvent.EventType = "Falco Security Event"

	stsContext.Category = "Alerts"
	stsContext.Source = "Falco"
	stsContext.ElementIdentifiers = createIdentifiers(falcopayload, stackstateConfig)

	stsEvent.Context = stsContext
	stsPayload.Events[falcopayload.UUID] = []eventPayload{stsEvent}
	stsPayload.CollectionTimestamp = falcopayload.Time.Unix()
	if falcopayload.Hostname != "" {
		stsPayload.InternalHostname = falcopayload.Hostname
	}

	return *stsPayload
}

func buildTags(falcopayload types.FalcoPayload) []string {
	var tags []string

	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			tags = append(tags, i+":"+v)
		default:
			continue
		}
	}

	tags = append(tags, "source:"+falcopayload.Source)
	if falcopayload.Hostname != "" {
		tags = append(tags, Hostname+":"+falcopayload.Hostname)
	}

	if len(falcopayload.Tags) != 0 {
		tags = append(tags, falcopayload.Tags...)
	}

	return tags
}

func createIdentifiers(falcoPayload types.FalcoPayload, stackstateConfig types.StackStateOutputConfig) []string {
	var identifiers []string = make([]string, 0)

	if falcoPayload.OutputFields != nil {
		var podName, namespaceName string
		if v, ok := falcoPayload.OutputFields["k8s.pod.name"]; ok {
			podName = v.(string)
		}

		if v, ok := falcoPayload.OutputFields["k8s.ns.name"]; ok {
			namespaceName = v.(string)
		}

		if podName != "" && namespaceName != "" {
			identifiers = append(identifiers, fmt.Sprintf("urn:kubernetes:/%s:%s:pod/%s", stackstateConfig.ClusterName, namespaceName, podName))
		}
	}

	return identifiers
}

// StackStatePost posts event to StackState
func (c *Client) StackStatePost(falcopayload types.FalcoPayload) {
	c.Stats.StackState.Add(Total, 1)

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()

	err := c.Post(newStackStatePayload(falcopayload, c.Config.StackState))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:stackstate", "status:error"})
		c.Stats.StackState.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "stackstate", "status": Error}).Inc()
		log.Printf("[ERROR] : StackState - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:stackstate", "status:ok"})
	c.Stats.StackState.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "stackstate", "status": OK}).Inc()
}
