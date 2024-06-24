// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// TalonPost posts event to an URL
func (c *Client) TalonPost(falcopayload types.FalcoPayload) {
	c.Stats.Talon.Add(Total, 1)

	err := c.Post(falcopayload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:talon", "status:error"})
		c.Stats.Talon.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "talon", "status": Error}).Inc()
		log.Printf("[ERROR] : Talon - %v\n", err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:talon", "status:ok"})
	c.Stats.Talon.Add(OK, 1)
	fmt.Println("aaaaa")
	c.PromStats.Outputs.With(map[string]string{"destination": "talon", "status": OK}).Inc()
}
