package outputs

import (
	"github.com/Issif/falcosidekick/types"
)

const (
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
	var ddpayload datadogPayload
	var tags []string

	for i, j := range falcopayload.OutputFields {
		switch j.(type) {
		case string:
			tags = append(tags, i+":"+j.(string))
		}
	}
	ddpayload.Tags = tags

	ddpayload.Title = falcopayload.Rule
	ddpayload.Text = falcopayload.Output
	ddpayload.SourceType = "falco"

	var status string
	switch falcopayload.Priority {
	case "Emergency", "Alert", "Critical", "Error":
		status = "error"
	case "Warning":
		status = "warning"
	default:
		status = "info"
	}
	ddpayload.AlertType = status

	return ddpayload
}

// DatadogPost posts event to Datadog
func (c *Client) DatadogPost(falcopayload types.FalcoPayload) {
	c.Post(newDatadogPayload(falcopayload))
}
