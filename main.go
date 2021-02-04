package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/outputs"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Globale variables
var (
	nullClient          *outputs.Client
	slackClient         *outputs.Client
	rocketchatClient    *outputs.Client
	mattermostClient    *outputs.Client
	teamsClient         *outputs.Client
	datadogClient       *outputs.Client
	discordClient       *outputs.Client
	alertmanagerClient  *outputs.Client
	elasticsearchClient *outputs.Client
	influxdbClient      *outputs.Client
	lokiClient          *outputs.Client
	natsClient          *outputs.Client
	stanClient          *outputs.Client
	awsClient           *outputs.Client
	smtpClient          *outputs.Client
	opsgenieClient      *outputs.Client
	webhookClient       *outputs.Client
	cloudeventsClient   *outputs.Client
	azureClient         *outputs.Client
	gcpClient           *outputs.Client
	googleChatClient    *outputs.Client
	kafkaClient         *outputs.Client
	pagerdutyClient     *outputs.Client
	kubelessClient      *outputs.Client
	webUIClient         *outputs.Client

	statsdClient, dogstatsdClient *statsd.Client
	config                        *types.Configuration
	stats                         *types.Statistics
	promStats                     *types.PromStatistics
)

func init() {
	config = getConfig()
	stats = getInitStats()
	promStats = getInitPromStats()

	config.UUID = uuid.New().String()

	if config.Statsd.Forwarder != "" {
		var err error
		statsdClient, err = outputs.NewStatsdClient("StatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "StatsD")
		}
	}

	if config.Dogstatsd.Forwarder != "" {
		var err error
		dogstatsdClient, err = outputs.NewStatsdClient("DogStatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "StatsD")
			nullClient.DogstatsdClient = dogstatsdClient
		}
	}

	nullClient = &outputs.Client{
		OutputType:      "null",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}

	if config.Slack.WebhookURL != "" {
		var err error
		slackClient, err = outputs.NewClient("Slack", config.Slack.WebhookURL, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Slack.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Slack")
		}
	}

	if config.Rocketchat.WebhookURL != "" {
		var err error
		rocketchatClient, err = outputs.NewClient("Rocketchat", config.Rocketchat.WebhookURL, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Rocketchat.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Rocketchat")
		}
	}

	if config.Mattermost.WebhookURL != "" {
		var err error
		mattermostClient, err = outputs.NewClient("Mattermost", config.Mattermost.WebhookURL, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Mattermost.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Mattermost")
		}
	}

	if config.Teams.WebhookURL != "" {
		var err error
		teamsClient, err = outputs.NewClient("Teams", config.Teams.WebhookURL, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Teams.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Teams")
		}
	}

	if config.Datadog.APIKey != "" {
		var err error
		datadogClient, err = outputs.NewClient("Datadog", config.Datadog.Host+outputs.DatadogPath+"?api_key="+config.Datadog.APIKey, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Datadog.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Datadog")
		}
	}

	if config.Discord.WebhookURL != "" {
		var err error
		discordClient, err = outputs.NewClient("Discord", config.Discord.WebhookURL, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Discord.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Discord")
		}
	}

	if config.Alertmanager.HostPort != "" {
		var err error
		alertmanagerClient, err = outputs.NewClient("AlertManager", config.Alertmanager.HostPort+outputs.AlertmanagerURI, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Alertmanager.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AlertManager")
		}
	}

	if config.Elasticsearch.HostPort != "" {
		var err error
		elasticsearchClient, err = outputs.NewClient("Elasticsearch", config.Elasticsearch.HostPort+"/"+config.Elasticsearch.Index+"/"+config.Elasticsearch.Type, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Elasticsearch.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Elasticsearch")
		}
	}

	if config.Loki.HostPort != "" {
		var err error
		lokiClient, err = outputs.NewClient("Loki", config.Loki.HostPort+"/api/prom/push", config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Loki.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Loki")
		}
	}

	if config.Nats.HostPort != "" {
		var err error
		natsClient, err = outputs.NewClient("NATS", config.Nats.HostPort, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Nats.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "NATS")
		}
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" {
		var err error
		stanClient, err = outputs.NewClient("STAN", config.Stan.HostPort, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Stan.HostPort = ""
			config.Stan.ClusterID = ""
			config.Stan.ClientID = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "STAN")
		}
	}

	if config.Influxdb.HostPort != "" {
		var credentials string
		if config.Influxdb.User != "" && config.Influxdb.Password != "" {
			credentials = "&u=" + config.Influxdb.User + "&p=" + config.Influxdb.Password
		}

		var err error
		influxdbClient, err = outputs.NewClient("Influxdb", config.Influxdb.HostPort+"/write?db="+config.Influxdb.Database+credentials, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Influxdb.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Influxdb")
		}
	}

	if config.AWS.Lambda.FunctionName != "" || config.AWS.SQS.URL != "" ||
		config.AWS.SNS.TopicArn != "" || config.AWS.CloudWatchLogs.LogGroup != "" {
		var err error
		awsClient, err = outputs.NewAWSClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.AWS.AccessKeyID = ""
			config.AWS.SecretAccessKey = ""
			config.AWS.Region = ""
			config.AWS.Lambda.FunctionName = ""
			config.AWS.SQS.URL = ""
			config.AWS.SNS.TopicArn = ""
			config.AWS.CloudWatchLogs.LogGroup = ""
			config.AWS.CloudWatchLogs.LogStream = ""
		} else {
			if config.AWS.Lambda.FunctionName != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSLambda")
			}
			if config.AWS.SQS.URL != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSSQS")
			}
			if config.AWS.SNS.TopicArn != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSSNS")
			}
			if config.AWS.CloudWatchLogs.LogGroup != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSCloudWatchLogs")
			}
		}
	}

	if config.SMTP.HostPort != "" && config.SMTP.From != "" && config.SMTP.To != "" {
		var err error
		smtpClient, err = outputs.NewSMTPClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.SMTP.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "SMTP")
		}
	}

	if config.Opsgenie.APIKey != "" {
		var err error
		url := "https://api.opsgenie.com/v2/alerts"
		if strings.ToLower(config.Opsgenie.Region) == "eu" {
			url = "https://api.eu.opsgenie.com/v2/alerts"
		}
		opsgenieClient, err = outputs.NewClient("Opsgenie", url, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Opsgenie.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Opsgenie")
		}
	}

	if config.Webhook.Address != "" {
		var err error
		webhookClient, err = outputs.NewClient("Webhook", config.Webhook.Address, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Webhook.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Webhook")
		}
	}

	if config.CloudEvents.Address != "" {
		var err error
		cloudeventsClient, err = outputs.NewClient("CloudEvents", config.CloudEvents.Address, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.CloudEvents.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "CloudEvents")
		}
	}

	if config.Azure.EventHub.Name != "" {
		var err error
		azureClient, err = outputs.NewEventHubClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Azure.EventHub.Name = ""
			config.Azure.EventHub.Namespace = ""
		} else {
			if config.Azure.EventHub.Name != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "EventHub")
			}
		}
	}

	if config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "" && config.GCP.Credentials != "" {
		var err error
		gcpClient, err = outputs.NewGCPClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.GCP.PubSub.ProjectID = ""
			config.GCP.PubSub.Topic = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPPubSub")
		}
	}

	if config.Googlechat.WebhookURL != "" {
		var err error
		googleChatClient, err = outputs.NewClient("Googlechat", config.Googlechat.WebhookURL, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Googlechat.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Google Chat")
		}
	}

	if config.Kafka.HostPort != "" && config.Kafka.Topic != "" {
		var err error
		kafkaClient, err = outputs.NewKafkaClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Kafka.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Kafka")
		}
	}

	if config.Pagerduty.APIKey != "" && config.Pagerduty.Service != "" {
		var err error
		pagerdutyClient, err = outputs.NewPagerdutyClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Pagerduty.APIKey = ""
			config.Pagerduty.Service = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Pagerduty")
		}
	}

	if config.Kubeless.Namespace != "" && config.Kubeless.Function != "" {
		var err error
		kubelessClient, err = outputs.NewKubelessClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			log.Printf("[ERROR] : Kubeless - %v\n", err)
			config.Kubeless.Namespace = ""
			config.Kubeless.Function = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Kubeless")
		}
	}

	if config.Webhook.Address != "" {
		var err error
		webhookClient, err = outputs.NewClient("Webhook", config.Webhook.Address, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Webhook.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Webhook")
		}
	}

	if config.WebUI.Address != "" {
		var err error
		webUIClient, err = outputs.NewClient("WebUI", config.WebUI.Address, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.WebUI.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "WebUI")
		}
	}

	log.Printf("[INFO]  : Enabled Outputs : %s\n", outputs.EnabledOutputs)
}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/healthz", healthHandler)
	http.HandleFunc("/test", testHandler)
	http.Handle("/metrics", promhttp.Handler())

	log.Printf("[INFO]  : Falco Sidekick is up and listening on port %v\n", config.ListenPort)
	if config.Debug {
		log.Printf("[INFO]  : Debug mode : %v\n", config.Debug)
	}

	if err := http.ListenAndServe(":"+strconv.Itoa(config.ListenPort), nil); err != nil {
		log.Fatalf("[ERROR] : %v\n", err.Error())
	}
}
