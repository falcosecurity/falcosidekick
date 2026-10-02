// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

const (
	// OutputWebUI is the name of the WebUI output
	OutputWebUI = "output:webui"
)

type WebUIPayload struct {
	Event   types.FalcoPayload `json:"event"`
	Outputs []string           `json:"outputs"`
}

func newWebUIPayload(falcopayload types.FalcoPayload) WebUIPayload {
	return WebUIPayload{
		Event:   falcopayload,
		Outputs: EnabledOutputs,
	}
}

// webUIError records an error and updates metrics (de-duplicates error handling)
func (c *Client) webUIError(err error, logErr string) {
	go c.CountMetric(Outputs, 1, []string{OutputWebUI, "status:error"})
	c.Stats.WebUI.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": Error}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "webui"),
		attribute.String("status", Error)).Inc()
	utils.Log(utils.ErrorLvl, c.OutputType, logErr)
}

// WebUIPost posts event to WebUI
func (c *Client) WebUIPost(falcopayload types.FalcoPayload) {
	c.Stats.WebUI.Add(Total, 1)

	var opts []RequestOptionFunc

	// Add authorization header if token provider is configured
	if c.WebUITokenSource != nil {
		ctx := context.Background()
		token, err := c.WebUITokenSource.Token(ctx)
		if err != nil {
			// Rate-limit error log to once per 10 seconds
			c.webUITokenErrorMu.Lock()
			now := time.Now()
			shouldLog := now.Sub(c.webUITokenErrorLastLog) > 10*time.Second
			if shouldLog {
				c.webUITokenErrorLastLog = now
			}
			c.webUITokenErrorMu.Unlock()

			if shouldLog {
				c.webUIError(err, "failed to get token: "+err.Error())
			} else {
				// Still count metrics even if not logging
				go c.CountMetric(Outputs, 1, []string{OutputWebUI, "status:error"})
				c.Stats.WebUI.Add(Error, 1)
				c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": Error}).Inc()
				c.OTLPMetrics.Outputs.With(attribute.String("destination", "webui"),
					attribute.String("status", Error)).Inc()
			}
			return
		}
		opts = append(opts, func(req *http.Request) {
			req.Header.Set(AuthorizationHeaderKey, Bearer+" "+token)
		})
	}

	err := c.Post(newWebUIPayload(falcopayload), opts...)
	if err != nil {
		c.webUIError(err, err.Error())
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:webui", "status:ok"})
	c.Stats.WebUI.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "webui", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "webui"),
		attribute.String("status", OK)).Inc()
}
