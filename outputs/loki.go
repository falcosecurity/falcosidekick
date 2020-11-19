package outputs

import (
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

func newLokiPayload(falcopayload types.FalcoPayload, config *types.Configuration) lokiPayload {
	le := lokiEntry{Ts: falcopayload.Time.Format(time.RFC3339), Line: falcopayload.Output}
	ls := lokiStream{Entries: []lokiEntry{le}}

	var s string
	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			s += strings.Replace(strings.Replace(strings.Replace(i, ".", "", -1), "]", "", -1), "[", "", -1) + "=\"" + v + "\","
		default:
			continue
		}
	}

	s += "rule=\"" + falcopayload.Rule + "\","
	s += "priority=\"" + falcopayload.Priority + "\","

	ls.Labels = "{" + s[:len(s)-1] + "}"

	return lokiPayload{Streams: []lokiStream{ls}}
}

// LokiPost posts event to Loki
func (c *Client) LokiPost(falcopayload types.FalcoPayload) {
	err := c.Post(newLokiPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Loki.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "loki", "status": Error}).Inc()
	} else {
		c.Stats.Loki.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "loki", "status": OK}).Inc()
	}

	c.Stats.Loki.Add(Total, 1)
}
