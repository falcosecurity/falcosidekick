package outputs

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/Issif/falcosidekick/types"
)

const (
	datadogURL string = "https://api.datadoghq.com/api/v1/events"
)

type datadogPayload struct {
	Title      string   `json:"title,omitempty"`
	Text       string   `json:"text,omitempty"`
	AlertType  string   `json:"alert_type,omitempty"`
	SourceType string   `json:"source_type_name,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

func newDatadogPayload(falcopayload types.FalcoPayload) datadogPayload {
	var ddpayload datadogPayload
	var tags []string

	for i, j := range falcopayload.OutputFields {
		switch j.(type) {
		case string:
			tags = append(tags, i+":"+j.(string))
		}
	}
	ddpayload.Tags = tags

	ddpayload.Title = falcopayload.Rule
	ddpayload.Text = falcopayload.Output
	ddpayload.SourceType = "falco"

	var status string
	switch falcopayload.Priority {
	case "Emergency", "Alert", "Critical", "Error":
		status = "error"
	case "Warning":
		status = "warning"
	default:
		status = "info"
	}
	ddpayload.AlertType = status

	return ddpayload
}

func DatadogPost(falcopayload types.FalcoPayload) {
	datadogPayload := newDatadogPayload(falcopayload)
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(datadogPayload)

	if os.Getenv("DEBUG") == "true" {
		log.Printf("[DEBUG] : Datadog's payload : %v\n", b)
	}

	resp, err := http.Post(datadogURL+"?api_key="+os.Getenv("DATADOG_TOKEN"), "application/json; charset=utf-8", b)
	if err != nil {
		log.Printf("[ERROR] : Datadog - %v\n", err.Error())
	} else if resp.StatusCode != 202 {
		log.Printf("[ERROR] : Datadog - %v\n", resp)
	} else {
		log.Printf("[INFO] : Datadog - Post sent successfully\n")
	}
}
