package outputs

import (
	"github.com/Issif/falcosidekick/types"
)

// ElasticsearchPost posts event to Elasticsearch
func (c *Client) ElasticsearchPost(falcopayload types.FalcoPayload) {
	c.Post(falcopayload)
}
