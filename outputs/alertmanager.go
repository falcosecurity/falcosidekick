package outputs

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"../types"
)

const (
	alertmanagerURL string = "/api/v1/alerts"
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
			alertmanagerincident.Labels[strings.Replace(i, ".", "_", -1)] = j.(string) //AlertManger doesn't support dots in a label name
		}
	}

	alertmanagerincident.Annotations["info"] = falcopayload.Output
	alertmanagerincident.Annotations["summary"] = falcopayload.Rule

	var a []alertmanagerIncident

	a = append(a, alertmanagerincident)

	return a
}

// AlertmanagerPost posts event to Alert Manager
func AlertmanagerPost(falcopayload types.FalcoPayload) {
	alertmanagerPayload := newAlertmanagerPayload(falcopayload)
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(alertmanagerPayload)
	resp, err := http.Post(os.Getenv("ALERTMANAGER_HOST_PORT")+alertmanagerURL, "application/json; charset=utf-8", b)
	if err != nil {
		log.Printf("[ERROR] : (AlertManager) %v\n", err.Error())
	} else if resp.StatusCode != 200 {
		log.Printf("[ERROR] : (AlertManager) %v\n", resp)
	}
}
