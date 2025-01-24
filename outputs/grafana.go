// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
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

type grafanaOnCallPayload struct {
	AlertUID string `json:"alert_uid"`
	State    string `json:"state"`
	Title    string `json:"title"`
	Message  string `json:"message"`
}

// The Content-Type to send along with the request
const GrafanaContentType = "application/json"

func newGrafanaPayload(falcopayload types.FalcoPayload, config *types.Configuration) grafanaPayload {
	tags := []string{
		"falco",
		falcopayload.Priority.String(),
		falcopayload.Rule,
		falcopayload.Source,
	}
	if falcopayload.Hostname != "" {
		tags = append(tags, falcopayload.Hostname)
	}

	if config.Grafana.AllFieldsAsTags {
		for _, i := range falcopayload.OutputFields {
			tags = append(tags, fmt.Sprintf("%v", i))
		}
		if len(falcopayload.Tags) != 0 {
			tags = append(tags, falcopayload.Tags...)
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

func newGrafanaOnCallPayload(falcopayload types.FalcoPayload) grafanaOnCallPayload {
	return grafanaOnCallPayload{
		AlertUID: falcopayload.UUID,
		Title:    fmt.Sprintf("[%v] %v", falcopayload.Priority, falcopayload.Rule),
		State:    "alerting",
		Message:  falcopayload.Output,
	}
}

// GrafanaPost posts event to grafana
func (c *Client) GrafanaPost(falcopayload types.FalcoPayload) {
	c.Stats.Grafana.Add(Total, 1)
	c.ContentType = GrafanaContentType

	err := c.Post(newGrafanaPayload(falcopayload, c.Config), func(req *http.Request) {
		req.Header.Set("Authorization", Bearer+" "+c.Config.Grafana.APIKey)
		for i, j := range c.Config.Grafana.CustomHeaders {
			req.Header.Set(i, j)
		}
	})
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:grafana", "status:error"})
		c.Stats.Grafana.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "grafana", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "grafana"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:grafana", "status:ok"})
	c.Stats.Grafana.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "grafana", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "grafana"),
		attribute.String("status", OK)).Inc()
}

// GrafanaOnCallPost posts event to grafana onCall
func (c *Client) GrafanaOnCallPost(falcopayload types.FalcoPayload) {
	c.Stats.GrafanaOnCall.Add(Total, 1)
	c.ContentType = GrafanaContentType

	err := c.Post(newGrafanaOnCallPayload(falcopayload), func(req *http.Request) {
		for i, j := range c.Config.GrafanaOnCall.CustomHeaders {
			req.Header.Set(i, j)
		}
	})

	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:grafanaoncall", "status:error"})
		c.Stats.Grafana.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "grafanaoncall", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "grafanaoncall"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:grafanaoncall", "status:ok"})
	c.Stats.Grafana.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "grafanaoncall", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "grafanaoncall"),
		attribute.String("status", OK)).Inc()
}
