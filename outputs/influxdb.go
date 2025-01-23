// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"go.opentelemetry.io/otel/attribute"
	"log"
	"net/http"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

type influxdbPayload string

func newInfluxdbPayload(falcopayload types.FalcoPayload) influxdbPayload {
	s := "events,rule=" + strings.Replace(falcopayload.Rule, " ", "_", -1) + ",priority=" + falcopayload.Priority.String() + ",source=" + falcopayload.Source

	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			s += "," + i + "=" + strings.Replace(v, " ", "_", -1)
		default:
			continue
		}
	}

	if falcopayload.Hostname != "" {
		s += "," + Hostname + "=" + falcopayload.Hostname
	}

	if len(falcopayload.Tags) != 0 {
		s += ",tags=" + strings.Join(falcopayload.Tags, "_")
	}

	s += " value=\"" + falcopayload.Output + "\""

	return influxdbPayload(s)
}

// InfluxdbPost posts event to InfluxDB
func (c *Client) InfluxdbPost(falcopayload types.FalcoPayload) {
	c.Stats.Influxdb.Add(Total, 1)

	err := c.Post(newInfluxdbPayload(falcopayload), func(req *http.Request) {
		req.Header.Set("Accept", "application/json")

		if c.Config.Influxdb.Token != "" {
			req.Header.Set("Authorization", "Token "+c.Config.Influxdb.Token)
		}
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:influxdb", "status:error"})
		c.Stats.Influxdb.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "influxdb", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "influxdb"),
			attribute.String("status", Error)).Inc()
		log.Printf("[ERROR] : InfluxDB - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:influxdb", "status:ok"})
	c.Stats.Influxdb.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "influxdb", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "influxdb"),
		attribute.String("status", OK)).Inc()
}
