package outputs

import (
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
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
	case "emergency", Alert:
		prio = "P1"
	case Critical:
		prio = "P2"
	case Error:
		prio = "P3"
	case Warning:
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
		c.Stats.Opsgenie.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "opsgenie", "status": Error}).Inc()
	} else {
		c.Stats.Opsgenie.Add("ok", 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "opsgenie", "status": OK}).Inc()
	}

	c.Stats.Opsgenie.Add(Total, 1)
}
