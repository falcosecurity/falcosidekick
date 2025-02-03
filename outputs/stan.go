// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"strings"

	stan "github.com/nats-io/stan.go"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

// StanPublish publishes event to NATS Streaming
func (c *Client) StanPublish(falcopayload types.FalcoPayload) {
	c.Stats.Stan.Add(Total, 1)

	subject := c.Config.Stan.SubjectTemplate
	if len(subject) == 0 {
		subject = defaultNatsSubjects
	}

	subject = strings.ReplaceAll(subject, "<priority>", strings.ToLower(falcopayload.Priority.String()))
	subject = strings.ReplaceAll(subject, "<rule>", strings.Trim(slugRegExp.ReplaceAllString(strings.ToLower(falcopayload.Rule), "_"), "_"))

	nc, err := stan.Connect(c.Config.Stan.ClusterID, c.Config.Stan.ClientID, stan.NatsURL(c.EndpointURL.String()))
	if err != nil {
		c.setStanErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}
	defer nc.Close()

	j, err := json.Marshal(falcopayload)
	if err != nil {
		c.setStanErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	err = nc.Publish(subject, j)
	if err != nil {
		c.setStanErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:stan", "status:ok"})
	c.Stats.Stan.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "stan", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "stan"), attribute.String("status", OK)).Inc()
	utils.Log(utils.InfoLvl, c.OutputType, "Publish OK")
}

// setStanErrorMetrics set the error stats
func (c *Client) setStanErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:stan", "status:error"})
	c.Stats.Stan.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "stan", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "stan"),
		attribute.String("status", Error)).Inc()

}
