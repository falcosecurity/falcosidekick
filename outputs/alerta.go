package outputs

import (
	"encoding/json"

	"github.com/falcosecurity/falcosidekick/types"
)

type alertaPayload struct {
	// Resource and Event are the only two required fields
	Resource string `json:"resource"`
	Event    string `json:"event"`
	// All other fields are optional
	Environment string            `json:"environment,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	Correlate   []string          `json:"correlate,omitempty"`
	Status      string            `json:"status,omitempty"`
	Service     []string          `json:"service,omitempty"`
	Group       string            `json:"group,omitempty"`
	Value       string            `json:"value,omitempty"`
	Text        string            `json:"text,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Origin      string            `json:"origin,omitempty"`
	Type        string            `json:"type,omitempty"`
	// Note: this must be an ISO 8601 formatted string in UTC time
	// ex: 2017-06-19T11:16:19.744Z
	CreateTime string `json:"createTime,omitempty"`
	Timeout    int    `json:"timeout,omitempty"`
	RawData    string `json:"rawData,omitempty"`
}

func newAlertaPayload(falcopayload types.FalcoPayload) alertaPayload {
	var ap alertaPayload
	ap.Resource = "falco"
	ap.Event = falcopayload.Rule
	ap.Text = falcopayload.Output
	ap.CreateTime = falcopayload.Time.Format("2006-01-02T15:04:05.999Z")
	ap.Attributes = make(map[string]string)
	// set severity
	switch falcopayload.Priority {
	case types.Emergency, types.Alert, types.Critical:
		ap.Severity = "critical"
	case types.Error:
		ap.Severity = "major"
	case types.Warning, types.Notice:
		ap.Severity = "minor"
	default:
		ap.Severity = "warning"
	}
	// set attributes
	for i, j := range falcopayload.OutputFields {
		switch v := j.(type) {
		case string:
			ap.Attributes[i] = v
		default:
			continue
		}
	}
	// set rawdata to the json encoded falcopayload
	rdb, err := json.Marshal(falcopayload)
	if err == nil {
		ap.RawData = string(rdb)
	}
	return ap
}
