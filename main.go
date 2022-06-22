package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-go/statsd"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/falcosecurity/falcosidekick/outputs"
	"github.com/falcosecurity/falcosidekick/types"
)

// Globale variables
var (
	nullClient          *outputs.Client
	slackClient         *outputs.Client
	cliqClient          *outputs.Client
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
	noderedClient       *outputs.Client
	cloudeventsClient   *outputs.Client
	azureClient         *outputs.Client
	gcpClient           *outputs.Client
	googleChatClient    *outputs.Client
	kafkaClient         *outputs.Client
	kafkaRestClient     *outputs.Client
	pagerdutyClient     *outputs.Client
	gcpCloudRunClient   *outputs.Client
	kubelessClient      *outputs.Client
	openfaasClient      *outputs.Client
	webUIClient         *outputs.Client
	policyReportClient  *outputs.Client
	rabbitmqClient      *outputs.Client
	wavefrontClient     *outputs.Client
	fissionClient       *outputs.Client
	grafanaClient       *outputs.Client
	yandexClient        *outputs.Client
	syslogClient        *outputs.Client

	statsdClient, dogstatsdClient *statsd.Client
	config                        *types.Configuration
	stats                         *types.Statistics
	promStats                     *types.PromStatistics

	regPromLabels *regexp.Regexp
)

func init() {
	// detect unit testing and skip init.
	// see: https://github.com/alecthomas/kingpin/issues/187
	testing := (strings.HasSuffix(os.Args[0], ".test") ||
		strings.HasSuffix(os.Args[0], "__debug_bin"))
	if testing {
		return
	}

	regPromLabels, _ = regexp.Compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")

	config = getConfig()
	stats = getInitStats()
	promStats = getInitPromStats(config)

	nullClient = &outputs.Client{
		OutputType:      "null",
		Config:          config,
		Stats:           stats,
		PromStats:       promStats,
		StatsdClient:    statsdClient,
		DogstatsdClient: dogstatsdClient,
	}

	if config.Statsd.Forwarder != "" {
		var err error
		statsdClient, err = outputs.NewStatsdClient("StatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "StatsD")
			nullClient.DogstatsdClient = statsdClient
		}
	}

	if config.Dogstatsd.Forwarder != "" {
		var err error
		dogstatsdClient, err = outputs.NewStatsdClient("DogStatsD", config, stats)
		if err != nil {
			config.Statsd.Forwarder = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "DogStatsD")
			nullClient.DogstatsdClient = dogstatsdClient
		}
	}

	if config.Slack.WebhookURL != "" {
		var err error
		slackClient, err = outputs.NewClient("Slack", config.Slack.WebhookURL, config.Slack.MutualTLS, config.Slack.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Slack.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Slack")
		}
	}

	if config.Cliq.WebhookURL != "" {
		var err error
		cliqClient, err = outputs.NewClient("Cliq", config.Cliq.WebhookURL, config.Cliq.MutualTLS, config.Cliq.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Cliq.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Cliq")
		}
	}

	if config.Rocketchat.WebhookURL != "" {
		var err error
		rocketchatClient, err = outputs.NewClient("Rocketchat", config.Rocketchat.WebhookURL, config.Rocketchat.MutualTLS, config.Rocketchat.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Rocketchat.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Rocketchat")
		}
	}

	if config.Mattermost.WebhookURL != "" {
		var err error
		mattermostClient, err = outputs.NewClient("Mattermost", config.Mattermost.WebhookURL, config.Mattermost.MutualTLS, config.Mattermost.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Mattermost.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Mattermost")
		}
	}

	if config.Teams.WebhookURL != "" {
		var err error
		teamsClient, err = outputs.NewClient("Teams", config.Teams.WebhookURL, config.Teams.MutualTLS, config.Teams.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Teams.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Teams")
		}
	}

	if config.Datadog.APIKey != "" {
		var err error
		datadogClient, err = outputs.NewClient("Datadog", config.Datadog.Host+outputs.DatadogPath+"?api_key="+config.Datadog.APIKey, config.Datadog.MutualTLS, config.Datadog.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Datadog.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Datadog")
		}
	}

	if config.Discord.WebhookURL != "" {
		var err error
		discordClient, err = outputs.NewClient("Discord", config.Discord.WebhookURL, config.Discord.MutualTLS, config.Discord.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Discord.WebhookURL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Discord")
		}
	}

	if config.Alertmanager.HostPort != "" {
		var err error
		alertmanagerClient, err = outputs.NewClient("AlertManager", config.Alertmanager.HostPort+config.Alertmanager.Endpoint, config.Alertmanager.MutualTLS, config.Alertmanager.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Alertmanager.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AlertManager")
		}
	}

	if config.Elasticsearch.HostPort != "" {
		var err error
		elasticsearchClient, err = outputs.NewClient("Elasticsearch", config.Elasticsearch.HostPort+"/"+config.Elasticsearch.Index+"/"+config.Elasticsearch.Type, config.Elasticsearch.MutualTLS, config.Elasticsearch.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Elasticsearch.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Elasticsearch")
		}
	}

	if config.Loki.HostPort != "" {
		var err error
		lokiClient, err = outputs.NewClient("Loki", config.Loki.HostPort+config.Loki.Endpoint, config.Loki.MutualTLS, config.Loki.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Loki.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Loki")
		}
	}

	if config.Nats.HostPort != "" {
		var err error
		natsClient, err = outputs.NewClient("NATS", config.Nats.HostPort, config.Nats.MutualTLS, config.Nats.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Nats.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "NATS")
		}
	}

	if config.Stan.HostPort != "" && config.Stan.ClusterID != "" && config.Stan.ClientID != "" {
		var err error
		stanClient, err = outputs.NewClient("STAN", config.Stan.HostPort, config.Stan.MutualTLS, config.Stan.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
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
		influxdbClient, err = outputs.NewClient("Influxdb", config.Influxdb.HostPort+"/write?db="+config.Influxdb.Database+credentials, config.Influxdb.MutualTLS, config.Influxdb.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Influxdb.HostPort = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Influxdb")
		}
	}

	if config.AWS.Lambda.FunctionName != "" || config.AWS.SQS.URL != "" ||
		config.AWS.SNS.TopicArn != "" || config.AWS.CloudWatchLogs.LogGroup != "" || config.AWS.S3.Bucket != "" ||
		config.AWS.Kinesis.StreamName != "" {
		var err error
		awsClient, err = outputs.NewAWSClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.AWS.AccessKeyID = ""
			config.AWS.SecretAccessKey = ""
			config.AWS.Region = ""
			config.AWS.Lambda.FunctionName = ""
			config.AWS.SQS.URL = ""
			config.AWS.S3.Bucket = ""
			config.AWS.SNS.TopicArn = ""
			config.AWS.CloudWatchLogs.LogGroup = ""
			config.AWS.CloudWatchLogs.LogStream = ""
			config.AWS.Kinesis.StreamName = ""
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
			if config.AWS.S3.Bucket != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSS3")
			}
			if config.AWS.Kinesis.StreamName != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "AWSKinesis")
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
		opsgenieClient, err = outputs.NewClient("Opsgenie", url, config.Opsgenie.MutualTLS, config.Opsgenie.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Opsgenie.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Opsgenie")
		}
	}

	if config.Webhook.Address != "" {
		var err error
		webhookClient, err = outputs.NewClient("Webhook", config.Webhook.Address, config.Webhook.MutualTLS, config.Webhook.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Webhook.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Webhook")
		}
	}

	if config.NodeRed.Address != "" {
		var err error
		noderedClient, err = outputs.NewClient("NodeRed", config.NodeRed.Address, false, config.NodeRed.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.NodeRed.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "NodeRed")
		}
	}

	if config.CloudEvents.Address != "" {
		var err error
		cloudeventsClient, err = outputs.NewClient("CloudEvents", config.CloudEvents.Address, config.CloudEvents.MutualTLS, config.CloudEvents.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
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

	if (config.GCP.PubSub.ProjectID != "" && config.GCP.PubSub.Topic != "") || config.GCP.Storage.Bucket != "" || config.GCP.CloudFunctions.Name != "" {
		var err error
		gcpClient, err = outputs.NewGCPClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.GCP.PubSub.ProjectID = ""
			config.GCP.PubSub.Topic = ""
			config.GCP.Storage.Bucket = ""
			config.GCP.CloudFunctions.Name = ""
		} else {
			if config.GCP.PubSub.Topic != "" && config.GCP.PubSub.ProjectID != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPPubSub")
			}
			if config.GCP.Storage.Bucket != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPStorage")
			}
			if config.GCP.CloudFunctions.Name != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "GCPCloudFunctions")
			}
		}
	}

	if config.GCP.CloudRun.Endpoint != "" && config.GCP.CloudRun.JWT != "" {
		var err error
		var outputName = "GCPCloudRun"

		gcpCloudRunClient, err = outputs.NewClient(outputName, config.GCP.CloudRun.Endpoint, false, false, config, stats, promStats, statsdClient, dogstatsdClient)

		if err != nil {
			config.GCP.CloudRun.Endpoint = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
		}
	}

	if config.Googlechat.WebhookURL != "" {
		var err error
		googleChatClient, err = outputs.NewClient("Googlechat", config.Googlechat.WebhookURL, config.Googlechat.MutualTLS, config.Googlechat.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
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

	if config.KafkaRest.Address != "" {
		var err error
		kafkaRestClient, err = outputs.NewClient("KafkaRest", config.KafkaRest.Address, config.KafkaRest.MutualTLS, config.KafkaRest.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.KafkaRest.Address = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "KafkaRest")
		}
	}

	if config.Pagerduty.RoutingKey != "" {
		var err error
		var url = "https://events.pagerduty.com/v2/enqueue"
		var outputName = "Pagerduty"

		pagerdutyClient, err = outputs.NewClient(outputName, url, config.Pagerduty.MutualTLS, config.Pagerduty.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)

		if err != nil {
			config.Pagerduty.RoutingKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
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

	if config.WebUI.URL != "" {
		var err error
		webUIClient, err = outputs.NewClient("WebUI", config.WebUI.URL, config.WebUI.MutualTLS, config.WebUI.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.WebUI.URL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "WebUI")
		}
	}
	if config.PolicyReport.Enabled {
		var err error
		policyReportClient, err = outputs.NewPolicyReportClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.PolicyReport.Enabled = false
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "PolicyReport")
		}
	}
	if config.Openfaas.FunctionName != "" {
		var err error
		openfaasClient, err = outputs.NewOpenfaasClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			log.Printf("[ERROR] : OpenFaaS - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "OpenFaaS")
		}
	}

	if config.Rabbitmq.URL != "" && config.Rabbitmq.Queue != "" {
		var err error
		rabbitmqClient, err = outputs.NewRabbitmqClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Rabbitmq.URL = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "RabbitMQ")
		}
	}

	if config.Wavefront.EndpointType != "" && config.Wavefront.EndpointHost != "" {
		var err error
		wavefrontClient, err = outputs.NewWavefrontClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			log.Printf("[ERROR] : Wavefront - %v\n", err)
			config.Wavefront.EndpointHost = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Wavefront")
		}
	}

	if config.Fission.Function != "" {
		var err error
		fissionClient, err = outputs.NewFissionClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			log.Printf("[ERROR] : Fission - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputs.Fission)
		}
	}

	if config.Grafana.HostPort != "" && config.Grafana.APIKey != "" {
		var err error
		var outputName = "Grafana"
		grafanaClient, err = outputs.NewClient(outputName, config.Grafana.HostPort+"/api/annotations", config.Grafana.MutualTLS, config.Grafana.CheckCert, config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Grafana.HostPort = ""
			config.Grafana.APIKey = ""
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, outputName)
		}
	}

	if config.Yandex.S3.Bucket != "" {
		var err error
		yandexClient, err = outputs.NewYandexClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Yandex.S3.Bucket = ""
			log.Printf("[ERROR] : Yandex - %v\n", err)
		} else {
			if config.Yandex.S3.Bucket != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "YandexS3")
			}
		}
	}

	if config.Yandex.DataStreams.StreamName != "" {
		var err error
		yandexClient, err = outputs.NewYandexClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Yandex.DataStreams.StreamName = ""
			log.Printf("[ERROR] : Yandex - %v\n", err)
		} else {
			if config.Yandex.DataStreams.StreamName != "" {
				outputs.EnabledOutputs = append(outputs.EnabledOutputs, "YandexDataStreams")
			}
		}
	}

	if config.Syslog.Host != "" {
		var err error
		syslogClient, err = outputs.NewSyslogClient(config, stats, promStats, statsdClient, dogstatsdClient)
		if err != nil {
			config.Syslog.Host = ""
			log.Printf("[ERROR] : Syslog - %v\n", err)
		} else {
			outputs.EnabledOutputs = append(outputs.EnabledOutputs, "Syslog")
		}
	}

	log.Printf("[INFO]  : Falco Sidekick version: %s\n", GetVersionInfo().GitVersion)
	log.Printf("[INFO]  : Enabled Outputs : %s\n", outputs.EnabledOutputs)

}

func main() {
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/healthz", healthHandler)
	http.HandleFunc("/test", testHandler)
	http.Handle("/metrics", promhttp.Handler())

	log.Printf("[INFO]  : Falco Sidekick is up and listening on %s:%d", config.ListenAddress, config.ListenPort)
	if config.Debug {
		log.Printf("[INFO]  : Debug mode : %v", config.Debug)
	}

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort), nil); err != nil {
		log.Fatalf("[ERROR] : %v", err.Error())
	}
}
