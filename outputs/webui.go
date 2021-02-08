package outputs

import (
	"encoding/json"
	"expvar"
	"fmt"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

type WebUIPayload struct {
	UUID    string             `json:"uuid,omitempty"`
	Event   types.FalcoPayload `json:"event,omitempty"`
	Stats   map[string]int64   `json:"stats,omitempty"`
	Outputs []string           `json:"outputs,omitempty"`
}

func newWebUIPayload(falcopayload types.FalcoPayload, config *types.Configuration) WebUIPayload {
	s := new(map[string]int64)

	json.Unmarshal([]byte(fmt.Sprintf("%v", expvar.Get("falco.priority"))), &s)

	return WebUIPayload{
		UUID:    config.UUID,
		Event:   falcopayload,
		Stats:   *s,
		Outputs: EnabledOutputs,
	}
}

// WebUIPost posts event to Slack
func (c *Client) WebUIPost(falcopayload types.FalcoPayload) {
	c.Stats.WebUI.Add(Total, 1)

	err := c.Post(newWebUIPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:webui", "status:error"})
		c.Stats.WebUI.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": Error}).Inc()
		log.Printf("[ERROR] : WebUI - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:webui", "status:ok"})
	c.Stats.WebUI.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": OK}).Inc()
	log.Printf("[INFO]  : WebUI - Publish OK\n")
}
