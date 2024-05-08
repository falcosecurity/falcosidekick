// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"log"
	"regexp"
	"strings"

	nats "github.com/nats-io/nats.go"

	"github.com/falcosecurity/falcosidekick/types"
)

var slugRegularExpression = regexp.MustCompile("[^a-z0-9]+")

// NatsPublish publishes event to NATS
func (c *Client) NatsPublish(falcopayload types.FalcoPayload) {
	c.Stats.Nats.Add(Total, 1)

	nc, err := nats.Connect(c.EndpointURL.String())
	if err != nil {
		c.setNatsErrorMetrics()
		log.Printf("[ERROR] : NATS - %v\n", err)
		return
	}
	defer nc.Flush()
	defer nc.Close()

	r := strings.Trim(slugRegularExpression.ReplaceAllString(strings.ToLower(falcopayload.Rule), "_"), "_")
	j, err := json.Marshal(falcopayload)
	if err != nil {
		c.setStanErrorMetrics()
		log.Printf("[ERROR] : STAN - %v\n", err.Error())
		return
	}

	err = nc.Publish("falco."+strings.ToLower(falcopayload.Priority.String())+"."+r, j)
	if err != nil {
		c.setNatsErrorMetrics()
		log.Printf("[ERROR] : NATS - %v\n", err)
		return
	}

	go c.CountMetric("outputs", 1, []string{"output:nats", "status:ok"})
	c.Stats.Nats.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": OK}).Inc()
	log.Printf("[INFO]  : NATS - Publish OK\n")
}

// setNatsErrorMetrics set the error stats
func (c *Client) setNatsErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:nats", "status:error"})
	c.Stats.Nats.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": Error}).Inc()
}
