// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

type influxdbPayload string

// Escapers for the InfluxDB line protocol:
// https://docs.influxdata.com/influxdb/v2/reference/syntax/line-protocol/#special-characters
var (
	influxdbTagEscaper   = strings.NewReplacer(",", `\,`, "=", `\=`, " ", `\ `, "\n", `\n`)
	influxdbFieldEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)
)

func influxdbTag(key, value string) string {
	if value == "" {
		return ""
	}
	return "," + influxdbTagEscaper.Replace(key) + "=" + influxdbTagEscaper.Replace(value)
}

func newInfluxdbPayload(falcopayload types.FalcoPayload) influxdbPayload {
	s := "events" +
		influxdbTag("rule", strings.ReplaceAll(falcopayload.Rule, " ", "_")) +
		influxdbTag("priority", falcopayload.Priority.String()) +
		influxdbTag("source", falcopayload.Source)

	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			s += influxdbTag(i, strings.ReplaceAll(v, " ", "_"))
		default:
			continue
		}
	}

	if falcopayload.Hostname != "" {
		s += influxdbTag(Hostname, falcopayload.Hostname)
	}

	if len(falcopayload.Tags) != 0 {
		s += influxdbTag("tags", strings.Join(falcopayload.Tags, "_"))
	}

	s += " value=\"" + influxdbFieldEscaper.Replace(falcopayload.Output) + "\""

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
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:influxdb", "status:ok"})
	c.Stats.Influxdb.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "influxdb", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "influxdb"),
		attribute.String("status", OK)).Inc()
}
