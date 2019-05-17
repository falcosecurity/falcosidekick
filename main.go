package main

import (
	"log"
	"net/http"
	"strconv"

	"github.com/Issif/falcosidekick/outputs"
	"github.com/Issif/falcosidekick/types"
)

// Globale variables
var port string
var slackClient, datadogClient, alertmanagerClient, elasticsearchClient *outputs.Client
var config *types.Configuration

func init() {
	config = getConfig()

	enabledOutputsText := "[INFO]  : Enabled Outputs : "
	if config.Slack.Webhook_URL != "" {
		var err error
		slackClient, err = outputs.NewClient("Slack", config.Slack.Webhook_URL, config.Debug)
		if err != nil {
			config.Slack.Webhook_URL = ""
		} else {
			enabledOutputsText += "Slack "
		}
	}
	if config.Datadog.API_Key != "" {
		var err error
		datadogClient, err = outputs.NewClient("Datadog", outputs.DatadogURL+"?api_key="+config.Datadog.API_Key, config.Debug)
		if err != nil {
			config.Datadog.API_Key = ""
		} else {
			enabledOutputsText += "Datadog "
		}
	}
	if config.Alertmanager.Host_Port != "" {
		var err error
		alertmanagerClient, err = outputs.NewClient("AlertManager", config.Alertmanager.Host_Port+outputs.AlertmanagerURI, config.Debug)
		if err != nil {
			config.Alertmanager.Host_Port = ""
		} else {
			enabledOutputsText += "AlertManager "
		}
	}
	if config.Elasticsearch.Host_Port != "" {
		var err error
		elasticsearchClient, err = outputs.NewClient("Elasticsearch", config.Elasticsearch.Host_Port+"/"+config.Elasticsearch.Index+"/"+config.Elasticsearch.Type, config.Debug)
		if err != nil {
			config.Elasticsearch.Host_Port = ""
		} else {
			enabledOutputsText += "Elasticsearch "
		}
	}

	log.Printf("%v\n", enabledOutputsText)
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/test", testHandler)

	log.Printf("[INFO]  : Falco Sidekick is up and listening on port %v\n", config.Listen_Port)
	log.Printf("[INFO]  : Debug mode : %v\n", config.Debug)
	if err := http.ListenAndServe(":"+strconv.Itoa(config.Listen_Port), nil); err != nil {
		log.Fatalf("[ERROR] : %v\n", err.Error())
	}
}
