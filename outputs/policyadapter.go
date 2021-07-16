package outputs

import (
	"fmt"
	//"log"

	"github.com/falcosecurity/falcosidekick/types"
	// "github.com/google/uuid"
)

// WebUIPost posts event to Slack
func (c *Client) PolicyAdapterPost(falcopayload types.FalcoPayload) {
	fmt.Println("Hello world to policyadapter.go in outputs")
}
