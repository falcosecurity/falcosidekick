package outputs

import (
	"log"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

type lokiPayload struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Labels  string      `json:"labels"`
	Entries []lokiEntry `json:"entries"`
}

type lokiEntry struct {
	Ts   string `json:"ts"`
	Line string `json:"line"`
}

// The Content-Type to send along with the request
const LokiContentType = "application/json"

func newLokiPayload(falcopayload types.FalcoPayload, config *types.Configuration) lokiPayload {
	le := lokiEntry{Ts: falcopayload.Time.Format(time.RFC3339), Line: falcopayload.Output}
	ls := lokiStream{Entries: []lokiEntry{le}}

	var s string
	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			s += strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(i, ".", ""), "]", ""), "[", "") + "=\"" + strings.ReplaceAll(v, "\"", "") + "\","
		default:
			continue
		}
	}

	s += "rule=\"" + falcopayload.Rule + "\","
	s += "priority=\"" + falcopayload.Priority.String() + "\","

	ls.Labels = "{" + s[:len(s)-1] + "}"

	return lokiPayload{Streams: []lokiStream{ls}}
}

// LokiPost posts event to Loki
func (c *Client) LokiPost(falcopayload types.FalcoPayload) {
	c.Stats.Loki.Add(Total, 1)
	c.ContentType = LokiContentType
	if c.Config.Loki.Tenant != "" {
		c.AddHeader("X-Scope-OrgID", c.Config.Loki.Tenant)
	}

	err := c.Post(newLokiPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:loki", "status:error"})
		c.Stats.Loki.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "loki", "status": Error}).Inc()
		log.Printf("[ERROR] : Loki - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:loki", "status:ok"})
	c.Stats.Loki.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "loki", "status": OK}).Inc()
}
