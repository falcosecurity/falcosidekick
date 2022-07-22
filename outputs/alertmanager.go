package outputs

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

type alertmanagerPayload struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	EndsAt      time.Time         `json:"endsAt,omitempty"`
}

func newAlertmanagerPayload(falcopayload types.FalcoPayload, config *types.Configuration) []alertmanagerPayload {
	var amPayload alertmanagerPayload
	amPayload.Labels = make(map[string]string)
	amPayload.Annotations = make(map[string]string)
	replacer := strings.NewReplacer(".", "_", "[", "_", "]", "")

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
			amPayload.Labels[replacer.Replace(i)] = v
		case json.Number:
			amPayload.Labels[replacer.Replace(i)] = v.String()
		default:
			continue
		}
	}
	amPayload.Labels["source"] = "falco"
	amPayload.Labels["rule"] = falcopayload.Rule
	amPayload.Labels["eventsource"] = falcopayload.Source
	if len(falcopayload.Tags) != 0 {
		amPayload.Labels["tags"] = strings.Join(falcopayload.Tags, ",")
	}

	amPayload.Labels["priority"] = falcopayload.Priority.String()
	amPayload.Annotations["info"] = falcopayload.Output
	amPayload.Annotations["summary"] = falcopayload.Rule
	if config.Alertmanager.ExpiresAfter != 0 {
		amPayload.EndsAt = falcopayload.Time.Add(time.Duration(config.Alertmanager.ExpiresAfter) * time.Second)
	}
	for label, value := range config.Alertmanager.ExtraLabels {
		amPayload.Labels[label] = value
	}
	for annotation, value := range config.Alertmanager.ExtraAnnotations {
		amPayload.Annotations[annotation] = value
	}

	var a []alertmanagerPayload

	a = append(a, amPayload)

	return a
}

// AlertmanagerPost posts event to AlertManager
func (c *Client) AlertmanagerPost(falcopayload types.FalcoPayload) {
	c.Stats.Alertmanager.Add(Total, 1)

	err := c.Post(newAlertmanagerPayload(falcopayload, c.Config))
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
}
