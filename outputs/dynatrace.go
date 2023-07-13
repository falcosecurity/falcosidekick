package outputs

import (
	"log"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

type dtPayload struct {
	Payload []dtLogMessage `json:"payload"`
}

type dtLogMessage struct {
	Timestamp   string       `json:"timestamp"`
	Severity    string       `json:"severity,omitempty"`
	Content     dtLogContent `json:"content"`
	SpanID      string       `json:"span_id,omitempty"`
	Hostname    string       `json:"host.name,omitempty"`
	LogSource   string       `json:"log.source"`
	AuditAction string       `json:"audit.action"`
}

type dtLogContent struct {
	Output       string                 `json:"output"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Tags         []string               `json:"tags,omitempty"`
}

const DynatraceContentType = "application/json; charset=utf-8"

func newDynatracePayload(falcopayload types.FalcoPayload) dtPayload {
	message := dtLogMessage{
		Timestamp: falcopayload.Time.Format(time.RFC3339),
		Severity:  falcopayload.Priority.String(),
		Content: dtLogContent{
			Output:       falcopayload.Output,
			OutputFields: falcopayload.OutputFields,
			Tags:         falcopayload.Tags,
		},
		SpanID:      falcopayload.UUID,
		Hostname:    falcopayload.Hostname,
		LogSource:   falcopayload.Source,
		AuditAction: falcopayload.Rule,
	}

	return dtPayload{Payload: []dtLogMessage{message}}
}

func (c *Client) DynatracePost(falcopayload types.FalcoPayload) {
	c.Stats.Dynatrace.Add(Total, 1)

	c.ContentType = DynatraceContentType

	if c.Config.Dynatrace.APIToken != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.AddHeader("Authorization", "Api-Token "+c.Config.Dynatrace.APIToken)
	}

	err := c.Post(newDynatracePayload(falcopayload).Payload)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:dynatrace", "status:error"})
		c.Stats.Dynatrace.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "dynatrace", "status": Error}).Inc()
		log.Printf("[ERROR] : Dynatrace - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:dynatrace", "status:ok"})
	c.Stats.Dynatrace.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "dynatrace", "status": OK}).Inc()
}
