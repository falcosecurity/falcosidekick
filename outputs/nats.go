// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"regexp"
	"strings"

	nats "github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

var slugRegExp = regexp.MustCompile("[^a-z0-9]+")

const defaultNatsSubjects = "falco.<priority>.<rule>"

// NatsPublish publishes event to NATS
func (c *Client) NatsPublish(falcopayload types.FalcoPayload) {
	c.Stats.Nats.Add(Total, 1)

	subject := c.Config.Nats.SubjectTemplate
	if len(subject) == 0 {
		subject = defaultNatsSubjects
	}

	subject = strings.ReplaceAll(subject, "<priority>", strings.ToLower(falcopayload.Priority.String()))
	subject = strings.ReplaceAll(subject, "<rule>", strings.Trim(slugRegExp.ReplaceAllString(strings.ToLower(falcopayload.Rule), "_"), "_"))

	nc, err := nats.Connect(c.EndpointURL.String())
	if err != nil {
		c.setNatsErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}
	defer nc.Flush()
	defer nc.Close()

	j, err := json.Marshal(falcopayload)
	if err != nil {
		c.setNatsErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	err = nc.Publish(subject, j)
	if err != nil {
		c.setNatsErrorMetrics()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric("outputs", 1, []string{"output:nats", "status:ok"})
	c.Stats.Nats.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "nats"), attribute.String("status", OK)).Inc()
	utils.Log(utils.InfoLvl, c.OutputType, "Publish OK")
}

// setNatsErrorMetrics set the error stats
func (c *Client) setNatsErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:nats", "status:error"})
	c.Stats.Nats.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "nats"),
		attribute.String("status", Error)).Inc()

}
