package outputs

import (
	"github.com/Issif/falcosidekick/types"
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
		}
	}
	d.Tags = tags

	d.Title = falcopayload.Rule
	d.Text = falcopayload.Output
	d.SourceType = "falco"

	var status string
	switch falcopayload.Priority {
	case "Emergency", "Alert", "Critical", "Error":
		status = "error"
	case "Warning":
		status = "warning"
	default:
		status = "info"
	}
	d.AlertType = status

	return d
}

// DatadogPost posts event to Datadog
func (c *Client) DatadogPost(falcopayload types.FalcoPayload) {
	c.Post(newDatadogPayload(falcopayload))
}
