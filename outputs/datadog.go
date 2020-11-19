package outputs

import (
	"strings"

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
	var tags []string

	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			tags = append(tags, i+":"+v)
		default:
			continue
		}
	}
	d.Tags = tags

	d.Title = falcopayload.Rule
	d.Text = falcopayload.Output
	d.SourceType = "falco"

	var status string
	switch strings.ToLower(falcopayload.Priority) {
	case Emergency, Alert, Critical, Error:
		status = Error
	case Warning:
		status = Warning
	default:
		status = Info
	}
	d.AlertType = status

	return d
}

// DatadogPost posts event to Datadog
func (c *Client) DatadogPost(falcopayload types.FalcoPayload) {
	err := c.Post(newDatadogPayload(falcopayload))
	if err != nil {
		c.Stats.Datadog.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "datadog", "status": Error}).Inc()
	} else {
		c.Stats.Datadog.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "datadog", "status": OK}).Inc()
	}
	c.Stats.Datadog.Add(Total, 1)
}
