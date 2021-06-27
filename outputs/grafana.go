package outputs

import (
	"fmt"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

type grafanaPayload struct {
	DashboardID int      `json:"dashboardId,omitempty"`
	PanelID     int      `json:"panelId,omitempty"`
	Time        int64    `json:"time"`
	TimeEnd     int64    `json:"timeEnd"`
	Tags        []string `json:"tags"`
	Text        string   `json:"text"`
}

// The Content-Type to send along with the request
const GrafanaContentType = "application/json"

func newGrafanaPayload(falcopayload types.FalcoPayload, config *types.Configuration) grafanaPayload {
	tags := []string{
		"falco",
		falcopayload.Priority.String(),
		falcopayload.Rule,
	}
	if config.Grafana.AllFieldsAsTags {
		for _, i := range falcopayload.OutputFields {
			tags = append(tags, fmt.Sprintf("%v", i))
		}
	}

	g := grafanaPayload{
		Text:    falcopayload.Output,
		Time:    falcopayload.Time.UnixNano() / 1000000,
		TimeEnd: falcopayload.Time.UnixNano() / 1000000,
		Tags:    tags,
	}

	if config.Grafana.DashboardID != 0 {
		g.DashboardID = config.Grafana.DashboardID
	}
	if config.Grafana.PanelID != 0 {
		g.PanelID = config.Grafana.PanelID
	}

	return g
}

// GrafanaPost posts event to grafana
func (c *Client) GrafanaPost(falcopayload types.FalcoPayload) {
	c.Stats.Grafana.Add(Total, 1)
	c.ContentType = GrafanaContentType

	c.AddHeader("Authorization", "Bearer "+c.Config.Grafana.APIKey)

	err := c.Post(newGrafanaPayload(falcopayload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:grafana", "status:error"})
		c.Stats.Grafana.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "grafana", "status": Error}).Inc()
		log.Printf("[ERROR] : Grafana - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:grafana", "status:ok"})
	c.Stats.Grafana.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "grafana", "status": OK}).Inc()
}
