package outputs

import (
	"os"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	// AlertmanagerURI is default endpoint where to send events
	AlertmanagerURI string = "/api/v1/alerts"
)

var priorityMap = map[string]int{
	"emergency":     8,
	"alert":         7,
	"critical":      6,
	"error":         5,
	"warning":       4,
	"notice":        3,
	"informational": 2,
	"debug":         1,
	"":              0,
}

type alertmanagerPayload struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func newAlertmanagerPayload(falcopayload types.FalcoPayload) []alertmanagerPayload {
	var amPayload alertmanagerPayload
	amPayload.Labels = make(map[string]string)
	amPayload.Annotations = make(map[string]string)

	for i, j := range falcopayload.OutputFields {
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

	// convert priority to ves alertmanager severity
	var severity string
	switch strings.ToLower(falcopayload.Priority) {
	case "emergency", "alert", "critical":
		severity = "critical"
	case "error":
		severity = "major"
	default:
		severity = "minor"
	}
	// unless req. priority >= (error = 5) => drop
	if minpri, present := os.LookupEnv("ALERTMANAGER_MINIMUMPRIORITY"); present {
		if priorityMap[strings.ToLower(falcopayload.Priority)] < priorityMap[strings.ToLower(minpri)] {
			return []alertmanagerPayload{}
		}
	}
	amPayload.Labels["priority"] = strings.ToLower(falcopayload.Priority)
	amPayload.Labels["severity"] = severity

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
