package outputs

import (
	"github.com/falcosecurity/falcosidekick/types"
	"strings"
)

type opsgeniePayload struct {
	Message     string            `json:"message"`
	User        string            `json:"entity,omitempty"`
	Description string            `json:"description,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	Priority    string            `json:"priority,omitempty"`
}

func newOpsgeniePayload(falcopayload types.FalcoPayload, config *types.Configuration) opsgeniePayload {
	details := make(map[string]string, len(falcopayload.OutputFields))
	for i, j := range falcopayload.OutputFields {
		switch j.(type) {
		case string:
			details[i] = j.(string)
		}
	}

	var prio string
	switch strings.ToLower(falcopayload.Priority) {
	case "emergency", "alert", "critical":
		prio = "P1"
	case "error":
		prio = "P2"
	case "warning":
		prio = "P3"
	case "notice", "informationnal":
		prio = "P4"
	default:
		prio = "P5"
	}

	ogpayload := opsgeniePayload{
		Message:     falcopayload.Output,
		User:        "Falcosidekick",
		Description: falcopayload.Rule,
		Details:     details,
		Priority:    prio,
	}
	return ogpayload
}

// OpsgeniePost posts event to OpsGenie
func (c *Client) OpsgeniePost(falcopayload types.FalcoPayload) {
	err := c.Post(newOpsgeniePayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Opsgenie.Add("error", 1)
	} else {
		c.Stats.Opsgenie.Add("sent", 1)
	}
	c.Stats.Opsgenie.Add("total", 1)
}
