package outputs

import (
	"github.com/Issif/falcosidekick/types"
)

// ElasticsearchPost posts event to Elasticsearch
func (c *Client) ElasticsearchPost(falcopayload types.FalcoPayload) {
	err := c.Post(falcopayload)
	if err != nil {
		c.Stats.Elasticsearch.Add("error", 1)
	} else {
		c.Stats.Elasticsearch.Add("sent", 1)
	}
	c.Stats.Elasticsearch.Add("total", 1)
}
