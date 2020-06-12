package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/outputs"
	"github.com/falcosecurity/falcosidekick/types"
)

// Globale variables
var nullClient, slackClient, rocketchatClient, mattermostClient, teamsClient, datadogClient, alertmanagerClient, elasticsearchClient, influxdbClient, lokiClient, natsClient, awsClient, smtpClient, opsgenieClient, webhookClient *outputs.Client
var statsdClient, dogstatsdClient *statsd.Client
var config *types.Configuration
var stats *types.Statistics
var priorityMap map[string]int

func init() {
	config = getConfig()
	stats = getInitStats()
	priorityMap = getPriorityMap()

	enabledOutputsText := "[INFO]  : Enabled Outputs : "

	if config.Statsd.Forwarder != "" {
		var err error
		statsdClient, err = outputs.NewStatsdClient("StatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			enabledOutputsText += "StatsD "
		}
	}
	if config.Dogstatsd.Forwarder != "" {
		var err error
		dogstatsdClient, err = outputs.NewStatsdClient("DogStatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			enabledOutputsText += "StatsD "
			nullClient.DogstatsdClient = dogstatsdClient
		}
	}

	nullClient = &outputs.Client{
		OutputType:      "null",
		Config:          config,
		Stats:           stats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}

	if config.Slack.WebhookURL != "" {
		var err error
		slackClient, err = outputs.NewClient("Slack", config.Slack.WebhookURL, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Slack.WebhookURL = ""
		} else {
			enabledOutputsText += "Slack "
		}
	}
	if config.Rocketchat.WebhookURL != "" {
		var err error
		rocketchatClient, err = outputs.NewClient("Rocketchat", config.Rocketchat.WebhookURL, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Rocketchat.WebhookURL = ""
		} else {
			enabledOutputsText += "Rocketchat "
		}
	}
	if config.Mattermost.WebhookURL != "" {
		var err error
		mattermostClient, err = outputs.NewClient("Mattermost", config.Mattermost.WebhookURL, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Mattermost.WebhookURL = ""
		} else {
			enabledOutputsText += "Mattermost "
		}
	}
	if config.Teams.WebhookURL != "" {
		var err error
		teamsClient, err = outputs.NewClient("Teams", config.Teams.WebhookURL, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Teams.WebhookURL = ""
		} else {
			enabledOutputsText += "Teams "
		}
	}
	if config.Datadog.APIKey != "" {
		var err error
		datadogClient, err = outputs.NewClient("Datadog", config.Datadog.Host+outputs.DatadogPath+"?api_key="+config.Datadog.APIKey, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Datadog.APIKey = ""
		} else {
			enabledOutputsText += "Datadog "
		}
	}
	if config.Alertmanager.HostPort != "" {
		var err error
		alertmanagerClient, err = outputs.NewClient("AlertManager", config.Alertmanager.HostPort+outputs.AlertmanagerURI, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Alertmanager.HostPort = ""
		} else {
			enabledOutputsText += "AlertManager "
		}
	}
	if config.Elasticsearch.HostPort != "" {
		var err error
		elasticsearchClient, err = outputs.NewClient("Elasticsearch", config.Elasticsearch.HostPort+"/"+config.Elasticsearch.Index+"/"+config.Elasticsearch.Type, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Elasticsearch.HostPort = ""
		} else {
			enabledOutputsText += "Elasticsearch "
		}
	}
	if config.Loki.HostPort != "" {
		var err error
		lokiClient, err = outputs.NewClient("Loki", config.Loki.HostPort+"/api/prom/push", config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Loki.HostPort = ""
		} else {
			enabledOutputsText += "Loki "
		}
	}
	if config.Nats.HostPort != "" {
		var err error
		natsClient, err = outputs.NewClient("NATS", config.Nats.HostPort, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Nats.HostPort = ""
		} else {
			enabledOutputsText += "NATS "
		}
	}
	if config.Influxdb.HostPort != "" {
		var credentials string
		if config.Influxdb.User != "" && config.Influxdb.Password != "" {
			credentials = "&u=" + config.Influxdb.User + "&p=" + config.Influxdb.Password
		}
		var err error
		influxdbClient, err = outputs.NewClient("Influxdb", config.Influxdb.HostPort+"/write?db="+config.Influxdb.Database+credentials, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Influxdb.HostPort = ""
		} else {
			enabledOutputsText += "Influxdb "
		}
	}
	if config.AWS.Lambda.FunctionName != "" || config.AWS.SQS.URL != "" {
		var err error
		awsClient, err = outputs.NewAWSClient(config, stats, statsdClient, dogstatsdClient)
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
	if config.SMTP.HostPort != "" && config.SMTP.From != "" && config.SMTP.To != "" {
		var err error
		smtpClient, err = outputs.NewSMTPClient(config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.SMTP.HostPort = ""
		} else {
			enabledOutputsText += "SMTP "
		}
	}
	if config.Opsgenie.APIKey != "" {
		var err error
		url := "https://api.opsgenie.com/v2/alerts"
		if strings.ToLower(config.Opsgenie.Region) == "eu" {
			url = "https://api.eu.opsgenie.com/v2/alerts"
		}
		opsgenieClient, err = outputs.NewClient("Opsgenie", url, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Opsgenie.APIKey = ""
		} else {
			enabledOutputsText += "Opsgenie "
		}
	}
	if config.Webhook.Address != "" {
		var err error
		webhookClient, err = outputs.NewClient("Webhook", config.Webhook.Address, config, stats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Webhook.Address = ""
		} else {
			enabledOutputsText += "Webhook "
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
