package outputs

import (
	"strconv"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	// AlertmanagerURI is default endpoint where to send events
	AlertmanagerURI string = "/api/v1/alerts"
)

type alertmanagerPayload struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func newAlertmanagerPayload(falcopayload types.FalcoPayload) []alertmanagerPayload {
	var amPayload alertmanagerPayload
	amPayload.Labels = make(map[string]string)
	amPayload.Annotations = make(map[string]string)

	for i, j := range falcopayload.OutputFields {
		if strings.HasPrefix(i, "n_evts") {
			// avoid delta evts as label
			continue
		}
		// strip cardinalities of syscall drops
		if strings.HasPrefix(i, "n_drop") {
			d, err := strconv.ParseInt(j.(string), 10, 64)
			if err == nil {
				var jj string
				switch d {
				case d == 0:
					jj = "0"
					falcopayload.Priority = "warning"
				case d < 10 {
					jj = "<10"
					falcopayload.Priority = "warning"
				case d > 10000:
					jj = ">10000"
					falcopayload.Priority = "critical"
				case d > 1000 {
					jj = ">1000"
					falcopayload.Priority = "critical"
				case d > 100 {
					jj = ">100"
					falcopayload.Priority = "critical"
				case d > 10 {
					jj = ">10"
					falcopayload.Priority = "warning"
				default:
					jj = j.(string)
					falcopayload.Priority = "critical"
				}

				amPayload.Labels[i] = jj
			}
			continue
		}
		switch j.(type) {
		case string:
			//AlertManger doesn't support dots in a label name
			amPayload.Labels[strings.Replace(i, ".", "_", -1)] = j.(string)
		default:
			continue
		}
	}
	amPayload.Labels["source"] = "falco"
	amPayload.Labels["rule"] = falcopayload.Rule

	amPayload.Annotations["info"] = falcopayload.Output
	amPayload.Annotations["summary"] = falcopayload.Rule

	var a []alertmanagerPayload

	a = append(a, amPayload)

	return a
}

// AlertmanagerPost posts event to AlertManager
func (c *Client) AlertmanagerPost(falcopayload types.FalcoPayload) {
	err := c.Post(newAlertmanagerPayload(falcopayload))
	if err != nil {
		c.Stats.Alertmanager.Add("error", 1)
	} else {
		c.Stats.Alertmanager.Add("ok", 1)
	}
	c.Stats.Alertmanager.Add("total", 1)
}
