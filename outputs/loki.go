// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

const LokiOut string = "Loki"

type lokiPayload struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values []lokiValue       `json:"values"`
}

type lokiValue = []string

// The Content-Type to send along with the request
const LokiContentType = "application/json"

func newLokiPayload(falcopayload types.FalcoPayload, config *types.Configuration) lokiPayload {
	s := make(map[string]string)
	s["rule"] = falcopayload.Rule
	s["source"] = falcopayload.Source
	s["priority"] = falcopayload.Priority.String()

	if k8sNs, ok := falcopayload.OutputFields["k8s.ns.name"].(string); ok {
		s["k8s_ns_name"] = k8sNs
	}
	if k8sPod, ok := falcopayload.OutputFields["k8s.pod.name"].(string); ok {
		s["k8s_pod_name"] = k8sPod
	}

	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			for k := range config.Customfields {
				if i == k {
					s[strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(i, ".", "_"), "]", ""), "[", "")] = strings.ReplaceAll(v, "\"", "")
				}
			}
			for k := range config.Templatedfields {
				if i == k {
					s[strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(i, ".", "_"), "]", ""), "[", "")] = strings.ReplaceAll(v, "\"", "")
				}
			}
			for _, k := range config.Loki.ExtraLabelsList {
				if i == k {
					s[strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(i, ".", "_"), "]", ""), "[", "")] = strings.ReplaceAll(v, "\"", "")
				}
			}
		default:
			continue
		}
	}

	if falcopayload.Hostname != "" {
		s[Hostname] = falcopayload.Hostname
	}

	if len(falcopayload.Tags) != 0 {
		sort.Strings(falcopayload.Tags)
		s["tags"] = strings.Join(falcopayload.Tags, ",")
	}

	var v string
	if config.Loki.Format == "json" {
		v = falcopayload.String()
	} else {
		v = falcopayload.Output
	}

	return lokiPayload{Streams: []lokiStream{
		{
			Stream: s,
			Values: []lokiValue{[]string{fmt.Sprintf("%v", falcopayload.Time.UnixNano()), v}},
		},
	}}
}

func lokiConfigureTenant(cfg *types.Configuration, req *http.Request) {
	if cfg.Loki.Tenant != "" {
		req.Header.Set("X-Scope-OrgID", cfg.Loki.Tenant)
	}
}

func lokiConfigureAuth(cfg *types.Configuration, req *http.Request) {
	if cfg.Loki.User != "" && cfg.Loki.APIKey != "" {
		req.SetBasicAuth(cfg.Loki.User, cfg.Loki.APIKey)
	}
}

func lokiConfigureCustomHeaders(cfg *types.Configuration, req *http.Request) {
	for i, j := range cfg.Loki.CustomHeaders {
		req.Header.Set(i, j)
	}
}

// LokiPost posts event to Loki
func (c *Client) LokiPost(falcopayload types.FalcoPayload) {
	c.Stats.Loki.Add(Total, 1)
	c.ContentType = LokiContentType

	err := c.Post(newLokiPayload(falcopayload, c.Config), func(req *http.Request) {
		lokiConfigureTenant(c.Config, req)
		lokiConfigureAuth(c.Config, req)
		lokiConfigureCustomHeaders(c.Config, req)
	})

	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:loki", "status:error"})
		c.Stats.Loki.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "loki", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "loki"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, LokiOut, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:loki", "status:ok"})
	c.Stats.Loki.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "loki", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "loki"),
		attribute.String("status", OK)).Inc()
}
