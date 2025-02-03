// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

// Records are the items inside the request wrapper
type Records struct {
	Value string `json:"value"`
}

// KafkaRestPayload is the request wrapper for Kafka Rest
type KafkaRestPayload struct {
	Records []Records `json:"records"`
}

// KafkaRestPost posts event the Kafka Rest Proxy
func (c *Client) KafkaRestPost(falcopayload types.FalcoPayload) {
	c.Stats.KafkaRest.Add(Total, 1)

	var version int
	switch c.Config.KafkaRest.Version {
	case 2:
		version = c.Config.KafkaRest.Version
	case 1:
		version = c.Config.KafkaRest.Version
	default:
		version = 2
	}
	falcoMsg, err := json.Marshal(falcopayload)
	if err != nil {
		c.Stats.KafkaRest.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "kafkarest", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "kafkarest"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, fmt.Sprintf("failed to marshalling message: %v", err))
		return
	}

	c.ContentType = fmt.Sprintf("application/vnd.kafka.binary.v%d+json", version)

	payload := KafkaRestPayload{
		Records: []Records{{
			Value: base64.StdEncoding.EncodeToString(falcoMsg),
		}},
	}

	err = c.Post(payload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:kafkarest", "status:error"})
		c.Stats.KafkaRest.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "kafkarest", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "kafkarest"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:kafkarest", "status:ok"})
	c.Stats.KafkaRest.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "kafkarest", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "kafkarest"),
		attribute.String("status", OK)).Inc()
}
