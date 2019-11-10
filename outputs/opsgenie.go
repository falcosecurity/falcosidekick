package outputs

import (
	"github.com/falcosecurity/falcosidekick/types"
	"strings"
)

type opsgeniePayload struct {
	Message     string            `json:"message"`
	Entity      string            `json:"entity,omitempty"`
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
		default:
			continue
		}
	}

	var prio string
	switch strings.ToLower(falcopayload.Priority) {
	case "emergency", "alert":
		prio = "P1"
	case "critical":
		prio = "P2"
	case "error":
		prio = "P3"
	case "warning":
		prio = "P4"
	default:
		prio = "P5"
	}

	return opsgeniePayload{
		Message:     falcopayload.Output,
		Entity:      "Falcosidekick",
		Description: falcopayload.Rule,
		Details:     details,
		Priority:    prio,
	}
}

// OpsgeniePost posts event to OpsGenie
func (c *Client) OpsgeniePost(falcopayload types.FalcoPayload) {
	err := c.Post(newOpsgeniePayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Opsgenie.Add("error", 1)
	} else {
		c.Stats.Opsgenie.Add("ok", 1)
	}
	c.Stats.Opsgenie.Add("total", 1)
}
