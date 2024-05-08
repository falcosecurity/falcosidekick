// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"log"
	"net/url"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

// ElasticsearchPost posts event to Elasticsearch
func (c *Client) ElasticsearchPost(falcopayload types.FalcoPayload) {
	c.Stats.Elasticsearch.Add(Total, 1)

	current := time.Now()
	var eURL string
	switch c.Config.Elasticsearch.Suffix {
	case "none":
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "/" + c.Config.Elasticsearch.Type
	case "monthly":
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "-" + current.Format("2006.01") + "/" + c.Config.Elasticsearch.Type
	case "annually":
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "-" + current.Format("2006") + "/" + c.Config.Elasticsearch.Type
	default:
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "-" + current.Format("2006.01.02") + "/" + c.Config.Elasticsearch.Type
	}

	endpointURL, err := url.Parse(eURL)
	if err != nil {
		c.setElasticSearchErrorMetrics()
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		return
	}

	c.EndpointURL = endpointURL
	if c.Config.Elasticsearch.Username != "" && c.Config.Elasticsearch.Password != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.BasicAuth(c.Config.Elasticsearch.Username, c.Config.Elasticsearch.Password)
	}

	for i, j := range c.Config.Elasticsearch.CustomHeaders {
		c.AddHeader(i, j)
	}

	err = c.Post(falcopayload)
	if err != nil {
		c.setElasticSearchErrorMetrics()
		log.Printf("[ERROR] : ElasticSearch - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:elasticsearch", "status:ok"})
	c.Stats.Elasticsearch.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "elasticsearch", "status": OK}).Inc()
}

// setElasticSearchErrorMetrics set the error stats
func (c *Client) setElasticSearchErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:elasticsearch", "status:error"})
	c.Stats.Elasticsearch.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "elasticsearch", "status": Error}).Inc()
}
