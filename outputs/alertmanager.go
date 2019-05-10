package outputs

import (
	"strings"

	"github.com/Issif/falcosidekick/types"
)

const (
	AlertmanagerURI string = "/api/v1/alerts"
)

type alertmanagerIncident struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func newAlertmanagerPayload(falcopayload types.FalcoPayload) []alertmanagerIncident {
	var alertmanagerincident alertmanagerIncident
	alertmanagerincident.Labels = make(map[string]string)
	alertmanagerincident.Annotations = make(map[string]string)

	for i, j := range falcopayload.OutputFields {
		switch j.(type) {
		case string:
			//AlertManger doesn't support dots in a label name
			alertmanagerincident.Labels[strings.Replace(i, ".", "_", -1)] = j.(string)
		}
	}
	alertmanagerincident.Labels["source"] = "falco"
	alertmanagerincident.Labels["rule"] = falcopayload.Rule

	alertmanagerincident.Annotations["info"] = falcopayload.Output
	alertmanagerincident.Annotations["summary"] = falcopayload.Rule

	var a []alertmanagerIncident

	a = append(a, alertmanagerincident)

	return a
}

// AlertmanagerPost posts event to AlertManager
func (c *Client) AlertmanagerPost(falcopayload types.FalcoPayload) {
	c.Post(newAlertmanagerPayload(falcopayload))
}
