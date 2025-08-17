// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

const sourceType = "falcosidekick"

type splunkPayload struct {
	Event      types.FalcoPayload `json:"event"`
	SourceType string             `json:"sourcetype"`
}

func newSplunkPayload(falcopayload types.FalcoPayload) splunkPayload {
	return splunkPayload{
		Event:      falcopayload,
		SourceType: sourceType,
	}
}

// Splunk posts event to an URL
func (c *Client) Send(falcopayload types.FalcoPayload) {
	c.Stats.Splunk.Add(Total, 1)

	optfn := func(req *http.Request) {
		for i, j := range c.Config.Splunk.CustomHeaders {
			req.Header.Set(i, j)
		}
		if c.Config.Splunk.Token != "" {
			req.Header.Set("Authorization", "Splunk "+c.Config.Splunk.Token)
		}
	}

	err := c.Post(newSplunkPayload(falcopayload), optfn)

	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:splunk", "status:error"})
		c.Stats.Splunk.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "splunk", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "splunk"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:splunk", "status:ok"})
	c.Stats.Splunk.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "splunk", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "splunk"),
		attribute.String("status", OK)).Inc()
}
