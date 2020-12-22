package outputs

import (
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// GCSCCPost posts event to Google Cloud Security Command Center
func (c *Client) GCSCCPost(falcopayload types.FalcoPayload) {
	c.Stats.GCSCC.Add(Total, 1)

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:gcscc", "status:error"})
		c.Stats.GCSCC.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "gcscc", "status": Error}).Inc()
		log.Printf("[ERROR] : GCSCC - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:gcscc", "status:ok"})
	c.Stats.GCSCC.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "gcscc", "status": OK}).Inc()
	log.Printf("[INFO] : GCSCC - Post OK\n")
}
