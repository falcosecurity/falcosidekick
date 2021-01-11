package outputs

import (
	"log"
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
				switch {
				case d == 0:
					jj = "0"
					falcopayload.Priority = types.Warning
				case d < 10:
					jj = "<10"
					falcopayload.Priority = types.Warning
				case d > 10000:
					jj = ">10000"
					falcopayload.Priority = types.Critical
				case d > 1000:
					jj = ">1000"
					falcopayload.Priority = types.Critical
				case d > 100:
					jj = ">100"
					falcopayload.Priority = types.Critical
				case d > 10:
					jj = ">10"
					falcopayload.Priority = types.Warning
				default:
					jj = j.(string)
					falcopayload.Priority = types.Critical
				}

				amPayload.Labels[i] = jj
			}
			continue
		}
		switch v := j.(type) {
		case string:
			//AlertManger unsupported chars in a label name
			replacer := strings.NewReplacer(".", "_", "[", "_", "]", "")
			amPayload.Labels[replacer.Replace(i)] = v
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
	c.Stats.Alertmanager.Add(Total, 1)

	err := c.Post(newAlertmanagerPayload(falcopayload))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:alertmanager", "status:error"})
		c.Stats.Alertmanager.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "alertmanager", "status": Error}).Inc()
		log.Printf("[ERROR] : AlertManager - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:alertmanager", "status:ok"})
	c.Stats.Alertmanager.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "alertmanager", "status": OK}).Inc()
	log.Printf("[INFO]  : AlertManager - Publish OK\n")
}
