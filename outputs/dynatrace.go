// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

type dtPayload struct {
	Payload []dtLogMessage `json:"payload"`
}

type dtLogMessage struct {
	Timestamp             string       `json:"timestamp"`
	EventId               string       `json:"event.id,omitempty"`
	EventName             string       `json:"event.name,omitempty"`
	EventProvider         string       `json:"event.provider,omitempty"`
	Severity              string       `json:"severity,omitempty"`
	HostName              string       `json:"host.name,omitempty"`
	LogSource             string       `json:"log.source,omitempty"`
	Content               dtLogContent `json:"content"`
	MitreTechnique        string       `json:"mitre.technique,omitempty"`
	MitreTactic           string       `json:"mitre.tactic,omitempty"`
	ContainerId           string       `json:"container.id,omitempty"`
	ContainerName         string       `json:"container.name,omitempty"`
	ContainerImageName    string       `json:"container.image.name,omitempty"`
	K8sNamespaceName      string       `json:"k8s.namespace.name,omitempty"`
	K8sPodName            string       `json:"k8s.pod.name,omitempty"`
	K8sPodUid             string       `json:"k8s.pod.uid,omitempty"`
	ProcessExecutableName string       `json:"process.executable.name,omitempty"`
	SpanId                string       `json:"span.id,omitempty"`
}

type dtLogContent struct {
	Output       string                 `json:"output"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Tags         []string               `json:"tags,omitempty"`
}

const DynatraceContentType = "application/json; charset=utf-8"
const DynatraceEventProvider = "Falco"

// match MITRE techniques, e.g. "T1070", and sub-techniques, e.g. "T1055.008"
var MitreTechniqueRegEx = regexp.MustCompile(`T\d+\.?\d*`)

// match MITRE tactics, e.g. "mitre_execution"
var MitreTacticRegEx = regexp.MustCompile(`mitre_\w+`)

func newDynatracePayload(falcopayload types.FalcoPayload) dtPayload {
	message := dtLogMessage{
		Timestamp:     falcopayload.Time.Format(time.RFC3339),
		EventId:       falcopayload.UUID,
		EventName:     falcopayload.Rule,
		EventProvider: DynatraceEventProvider,
		Severity:      falcopayload.Priority.String(),
		HostName:      falcopayload.Hostname,
		LogSource:     falcopayload.Source,
		Content: dtLogContent{
			Output:       falcopayload.Output,
			OutputFields: falcopayload.OutputFields,
			Tags:         falcopayload.Tags,
		},
	}

	// possibly map a few fields to semantic attributes
	if falcopayload.OutputFields != nil {
		for fcKey, val := range falcopayload.OutputFields {
			if val == nil {
				continue
			}

			switch fcKey {
			case "container.id":
				message.ContainerId = val.(string)
			case "container.name":
				message.ContainerName = val.(string)
			case "container.image":
				message.ContainerImageName = val.(string)
			case "k8s.ns.name", "ka.target.namespace":
				message.K8sNamespaceName = val.(string)
			case "k8s.pod.name":
				message.K8sPodName = val.(string)
			case "k8s.pod.id":
				message.K8sPodUid = val.(string)
			case "proc.name":
				message.ProcessExecutableName = val.(string)
			case "span.id":
				message.SpanId = strconv.Itoa(val.(int))
			default:
				continue
			}
		}
	}

	// map tags to MITRE technique and tactic
	for _, fcTag := range falcopayload.Tags {
		if MitreTechniqueRegEx.MatchString(fcTag) {
			message.MitreTechnique = fcTag
		} else if MitreTacticRegEx.MatchString(fcTag) {
			message.MitreTactic = fcTag
		}
	}

	return dtPayload{Payload: []dtLogMessage{message}}
}

func (c *Client) DynatracePost(falcopayload types.FalcoPayload) {
	c.Stats.Dynatrace.Add(Total, 1)

	c.ContentType = DynatraceContentType

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	c.AddHeader("Authorization", "Api-Token "+c.Config.Dynatrace.APIToken)

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
