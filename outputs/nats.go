package outputs

import (
	"encoding/json"
	"log"
	"regexp"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
	nats "github.com/nats-io/nats.go"
)

var slugRegularExpression = regexp.MustCompile("[^a-z0-9]+")

// NatsPublish publishes event to NATS
func (c *Client) NatsPublish(falcopayload types.FalcoPayload) {
	nc, err := nats.Connect(c.EndpointURL.String())
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:nats", "status:error"})
		c.Stats.Nats.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": Error}).Inc()
		c.Stats.Nats.Add("total", 1)
		log.Printf("[ERROR] : NATS - %v\n", err)
		return
	}

	r := strings.Trim(slugRegularExpression.ReplaceAllString(strings.ToLower(falcopayload.Rule), "_"), "_")
	j, _ := json.Marshal(falcopayload)

	err = nc.Publish("falco."+strings.ToLower(falcopayload.Priority)+"."+r, j)
	if err != nil {
		go c.CountMetric("outputs", 1, []string{"output:nats", "status:error"})
		c.Stats.Nats.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": Error}).Inc()
		log.Printf("[ERROR] : NATS - %v\n", err)
	} else {
		go c.CountMetric("outputs", 1, []string{"output:nats", "status:ok"})
		c.Stats.Nats.Add(OK, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": OK}).Inc()
		log.Printf("[INFO]  : NATS - Publish OK\n")
	}
	defer nc.Flush()
	defer nc.Close()

	c.Stats.Nats.Add(Total, 1)
}
