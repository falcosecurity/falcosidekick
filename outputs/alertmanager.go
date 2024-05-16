// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"log"
	"regexp"
	"sort"
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

var defaultSeverityMap = map[types.PriorityType]string{
	types.Debug:         "information",
	types.Informational: "information",
	types.Notice:        "information",
	types.Warning:       "warning",
	types.Error:         "warning",
	types.Critical:      "critical",
	types.Alert:         "critical",
	types.Emergency:     "critical",
}

// labels should match [a-zA-Z_][a-zA-Z0-9_]*
var (
	reg = regexp.MustCompile("[^a-zA-Z0-9_]")
)

func newAlertmanagerPayload(falcopayload types.FalcoPayload, config *types.Configuration) []alertmanagerPayload {
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
				if d == 0 {
					if falcopayload.Priority < types.Warning {
						falcopayload.Priority = types.Warning
					}
					jj = "0"
				} else {
					for _, threshold := range config.Alertmanager.DropEventThresholdsList {
						if d > threshold.Value {
							jj = ">" + strconv.FormatInt(threshold.Value, 10)
							if falcopayload.Priority < threshold.Priority {
								falcopayload.Priority = threshold.Priority
							}
							break
						}
					}
				}
				if jj == "" {
					jj = j.(string)
					if prio := types.Priority(config.Alertmanager.DropEventDefaultPriority); falcopayload.Priority < prio {
						falcopayload.Priority = prio
					}
				}
				amPayload.Labels[i] = jj
			}
			continue
		}
		safeLabel := alertmanagerSafeLabel(i)
		switch v := j.(type) {
		case string:
			//AlertManger unsupported chars in a label name
			amPayload.Labels[safeLabel] = v
		case json.Number:
			amPayload.Labels[safeLabel] = v.String()
		default:
			continue
		}
	}
	amPayload.Labels["source"] = "falco"
	amPayload.Labels["rule"] = falcopayload.Rule
	amPayload.Labels["eventsource"] = falcopayload.Source
	if falcopayload.Hostname != "" {
		amPayload.Labels[Hostname] = falcopayload.Hostname
	}
	if len(falcopayload.Tags) != 0 {
		sort.Strings(falcopayload.Tags)
		amPayload.Labels["tags"] = strings.Join(falcopayload.Tags, ",")
	}

	amPayload.Labels["priority"] = falcopayload.Priority.String()

	if val, ok := config.Alertmanager.CustomSeverityMap[falcopayload.Priority]; ok {
		amPayload.Labels["severity"] = val
	} else {
		amPayload.Labels["severity"] = defaultSeverityMap[falcopayload.Priority]
	}

	amPayload.Annotations["info"] = falcopayload.Output
	amPayload.Annotations["description"] = falcopayload.Output
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
	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	for i, j := range c.Config.Alertmanager.CustomHeaders {
		c.AddHeader(i, j)
	}

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

func alertmanagerSafeLabel(label string) string {
	// replace all unsafe characters with _
	replaced := reg.ReplaceAllString(label, "_")
	// remove double __
	replaced = strings.ReplaceAll(replaced, "__", "_")
	// remove trailing _
	replaced = strings.TrimRight(replaced, "_")
	// remove leading _
	return strings.TrimLeft(replaced, "_")
}
