// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"sort"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	// DatadogPath is the path of Datadog's event API
	DatadogPath string = "/api/v1/events"
)

type datadogPayload struct {
	Title      string   `json:"title,omitempty"`
	Text       string   `json:"text,omitempty"`
	AlertType  string   `json:"alert_type,omitempty"`
	SourceType string   `json:"source_type_name,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

func newDatadogPayload(falcopayload types.FalcoPayload) datadogPayload {
	var d datadogPayload
	tags := make([]string, 0)

	for _, i := range getSortedStringKeys(falcopayload.OutputFields) {
		tags = append(tags, fmt.Sprintf("%v:%v", i, falcopayload.OutputFields[i]))

	}
	tags = append(tags, "source:"+falcopayload.Source)
	if falcopayload.Hostname != "" {
		tags = append(tags, Hostname+":"+falcopayload.Hostname)
	}

	if len(falcopayload.Tags) != 0 {
		sort.Strings(falcopayload.Tags)
		tags = append(tags, falcopayload.Tags...)
	}
	d.Tags = tags

	d.Title = falcopayload.Rule
	d.Text = falcopayload.Output
	d.SourceType = "falco"

	var status string
	switch falcopayload.Priority {
	case types.Emergency, types.Alert, types.Critical, types.Error:
		status = Error
	case types.Warning:
		status = Warning
	default:
		status = Info
	}
	d.AlertType = status

	return d
}

// DatadogPost posts event to Datadog
func (c *Client) DatadogPost(falcopayload types.FalcoPayload) {
	c.Stats.Datadog.Add(Total, 1)

	err := c.Post(newDatadogPayload(falcopayload))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:datadog", "status:error"})
		c.Stats.Datadog.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "datadog", "status": Error}).Inc()
		log.Printf("[ERROR] : Datadog - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:datadog", "status:ok"})
	c.Stats.Datadog.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "datadog", "status": OK}).Inc()
}
