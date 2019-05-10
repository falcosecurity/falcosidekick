package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/Issif/falcosidekick/outputs"
)

// Globale variables
var port string
var slackClient, datadogClient, alertmanagerClient *outputs.Client

func init() {
	port = "2801"
	if lport, err := strconv.Atoi(os.Getenv("LISTEN_PORT")); err == nil {
		if lport > 0 && lport < 65536 {
			port = os.Getenv("LISTEN_PORT")
		} else {
			log.Fatalf("[ERROR] : Bad port number\n")
		}
	}
	enableOutputsText := "[INFO] : Enable Outputs : "
	disableOutputsText := "[INFO] : Disable Outputs : "
	if os.Getenv("SLACK_WEBHOOK_URL") != "" {
		var err error
		slackClient, err = outputs.NewClient("Slack", os.Getenv("SLACK_WEBHOOK_URL"))
		if err != nil {
			disableOutputsText += "Slack "
		} else {
			enableOutputsText += "Slack "
		}
	} else {
		disableOutputsText += "Slack "
	}
	if os.Getenv("DATADOG_API_KEY") != "" {
		var err error
		datadogClient, err = outputs.NewClient("Datadog", outputs.DatadogURL+"?api_key="+os.Getenv("DATADOG_API_KEY"))
		if err != nil {
			disableOutputsText += "Datadog "
		} else {
			enableOutputsText += "Datadog "
		}
	} else {
		disableOutputsText += "Datadog "
	}
	if os.Getenv("ALERTMANAGER_HOST_PORT") != "" {
		var err error
		alertmanagerClient, err = outputs.NewClient("Alertmanager", os.Getenv("ALERTMANAGER_HOST_PORT")+outputs.AlertmanagerURI)
		if err != nil {
			disableOutputsText += "Alertmanager "
		} else {
			enableOutputsText += "Alertmanager "
		}
	} else {
		disableOutputsText += "Alertmanager "
	}

	log.Printf("%v\n", enableOutputsText)
	log.Printf("%v\n", disableOutputsText)
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/test", testHandler)

	log.Printf("[INFO] : Falco Sidekick is up and listening on port %v\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("[ERROR] : %v\n", err.Error())
	}
}
