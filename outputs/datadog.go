package outputs

import (
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	// DatadogURL is default URL of Datadog's API
	DatadogURL string = "https://api.datadoghq.com/api/v1/events"
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
		switch j.(type) {
		case string:
			tags = append(tags, i+":"+j.(string))
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
	case "emergency", "alert", "critical", "error":
		status = "error"
	case "warning":
		status = "warning"
	default:
		status = "info"
	}
	d.AlertType = status

	return d
}

// DatadogPost posts event to Datadog
func (c *Client) DatadogPost(falcopayload types.FalcoPayload) {
	err := c.Post(newDatadogPayload(falcopayload))
	if err != nil {
		c.Stats.Datadog.Add("error", 1)
	} else {
		c.Stats.Datadog.Add("ok", 1)
	}
	c.Stats.Datadog.Add("total", 1)
}
