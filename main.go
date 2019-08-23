package main

import (
	"log"
	"net/http"
	"strconv"

	"github.com/Issif/falcosidekick/outputs"
	"github.com/Issif/falcosidekick/types"
)

// Globale variables
var slackClient, teamsClient, datadogClient, alertmanagerClient, elasticsearchClient, influxdbClient, awsClient, smtpClient *outputs.Client
var config *types.Configuration
var stats *types.Statistics

func init() {
	config = getConfig()
	stats = getInitStats()

	enabledOutputsText := "[INFO]  : Enabled Outputs : "
	if config.Slack.WebhookURL != "" {
		var err error
		slackClient, err = outputs.NewClient("Slack", config.Slack.WebhookURL, config, stats)
		if err != nil {
			config.Slack.WebhookURL = ""
		} else {
			enabledOutputsText += "Slack "
		}
	}
	if config.Teams.WebhookURL != "" {
		var err error
		teamsClient, err = outputs.NewClient("Teams", config.Teams.WebhookURL, config, stats)
		if err != nil {
			config.Teams.WebhookURL = ""
		} else {
			enabledOutputsText += "Teams "
		}
	}
	if config.Datadog.APIKey != "" {
		var err error
		datadogClient, err = outputs.NewClient("Datadog", outputs.DatadogURL+"?apikey="+config.Datadog.APIKey, config, stats)
		if err != nil {
			config.Datadog.APIKey = ""
		} else {
			enabledOutputsText += "Datadog "
		}
	}
	if config.Alertmanager.HostPort != "" {
		var err error
		alertmanagerClient, err = outputs.NewClient("AlertManager", config.Alertmanager.HostPort+outputs.AlertmanagerURI, config, stats)
		if err != nil {
			config.Alertmanager.HostPort = ""
		} else {
			enabledOutputsText += "AlertManager "
		}
	}
	if config.Elasticsearch.HostPort != "" {
		var err error
		elasticsearchClient, err = outputs.NewClient("Elasticsearch", config.Elasticsearch.HostPort+"/"+config.Elasticsearch.Index+"/"+config.Elasticsearch.Type, config, stats)
		if err != nil {
			config.Elasticsearch.HostPort = ""
		} else {
			enabledOutputsText += "Elasticsearch "
		}
	}
	if config.Influxdb.HostPort != "" {
		var credentials string
		if config.Influxdb.User != "" && config.Influxdb.Password != "" {
			credentials = "&u=" + config.Influxdb.User + "&p=" + config.Influxdb.Password
		}
		var err error
		influxdbClient, err = outputs.NewClient("Influxdb", config.Influxdb.HostPort+"/write?db="+config.Influxdb.Database+credentials, config, stats)
		if err != nil {
			config.Influxdb.HostPort = ""
		} else {
			enabledOutputsText += "Influxdb "
		}
	}
	if config.AWS.Lambda.FunctionName != "" || config.AWS.SQS.URL != "" {
		var err error
		awsClient, err = outputs.NewAWSClient("AWS", config, stats)
		if err != nil {
			config.AWS.AccessKeyID = ""
			config.AWS.SecretAccessKey = ""
			config.AWS.Region = ""
			config.AWS.Lambda.FunctionName = ""
			config.AWS.SQS.URL = ""
		} else {
			if config.AWS.Lambda.FunctionName != "" {
				enabledOutputsText += "AWSLambda "
			}
			if config.AWS.SQS.URL != "" {
				enabledOutputsText += "AWSSQS "
			}
		}
	}
	if config.SMTP.ServerPort != "" && config.SMTP.From != "" && config.SMTP.To != "" {
		var err error
		smtpClient, err = outputs.NewSMTPClient("SMTP", config, stats)
		if err != nil {
			config.SMTP.ServerPort = ""
		} else {
			enabledOutputsText += "SMTP "
		}
	}

	log.Printf("%v\n", enabledOutputsText)
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/test", testHandler)

	log.Printf("[INFO]  : Falco Sidekick is up and listening on port %v\n", config.ListenPort)
	if config.Debug {
		log.Printf("[INFO]  : Debug mode : %v\n", config.Debug)
	}
	if err := http.ListenAndServe(":"+strconv.Itoa(config.ListenPort), nil); err != nil {
		log.Fatalf("[ERROR] : %v\n", err.Error())
	}
}
