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
	enabledOutputsText := "[INFO]  : Enabled Outputs : "
	if os.Getenv("SLACK_WEBHOOK_URL") != "" {
		var err error
		slackClient, err = outputs.NewClient("Slack", os.Getenv("SLACK_WEBHOOK_URL"))
		if err != nil {
			os.Unsetenv("SLACK_WEBHOOK_URL")
		} else {
			enabledOutputsText += "Slack "
		}
	}
	if os.Getenv("DATADOG_API_KEY") != "" {
		var err error
		datadogClient, err = outputs.NewClient("Datadog", outputs.DatadogURL+"?api_key="+os.Getenv("DATADOG_API_KEY"))
		if err != nil {
			os.Unsetenv("DATADOG_API_KEY")
		} else {
			enabledOutputsText += "Datadog "
		}
	}
	if os.Getenv("ALERTMANAGER_HOST_PORT") != "" {
		var err error
		alertmanagerClient, err = outputs.NewClient("Alertmanager", os.Getenv("ALERTMANAGER_HOST_PORT")+outputs.AlertmanagerURI)
		if err != nil {
			os.Unsetenv("ALERTMANAGER_HOST_PORT")
		} else {
			enabledOutputsText += "Alertmanager "
		}
	}

	log.Printf("%v\n", enabledOutputsText)
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/test", testHandler)

	log.Printf("[INFO]  : Falco Sidekick is up and listening on port %v\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("[ERROR] : %v\n", err.Error())
	}
}
