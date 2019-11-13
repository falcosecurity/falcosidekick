package outputs

import (
	"log"
	"net/url"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

// ElasticsearchPost posts event to Elasticsearch
func (c *Client) ElasticsearchPost(falcopayload types.FalcoPayload) {
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
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
	}
	c.EndpointURL = endpointURL
	err = c.Post(falcopayload)
	if err != nil {
		c.Stats.Elasticsearch.Add("error", 1)
	} else {
		c.Stats.Elasticsearch.Add("ok", 1)
	}
	c.Stats.Elasticsearch.Add("total", 1)
}
