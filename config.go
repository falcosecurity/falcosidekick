// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/spf13/viper"

	"github.com/falcosecurity/falcosidekick/types"
)

func getConfig() *types.Configuration {
	c := &types.Configuration{
		Customfields:    make(map[string]string),
		Templatedfields: make(map[string]string),
		TLSServer:       types.TLSServer{NoTLSPaths: make([]string, 0)},
		Grafana:         types.GrafanaOutputConfig{CustomHeaders: make(map[string]string)},
		Loki:            types.LokiOutputConfig{CustomHeaders: make(map[string]string)},
		Elasticsearch:   types.ElasticsearchOutputConfig{CustomHeaders: make(map[string]string)},
		Quickwit:        types.QuickwitOutputConfig{CustomHeaders: make(map[string]string)},
		OpenObserve:     types.OpenObserveConfig{CustomHeaders: make(map[string]string)},
		Webhook:         types.WebhookOutputConfig{CustomHeaders: make(map[string]string)},
		Alertmanager:    types.AlertmanagerOutputConfig{ExtraLabels: make(map[string]string), ExtraAnnotations: make(map[string]string), CustomSeverityMap: make(map[types.PriorityType]string), CustomHeaders: make(map[string]string)},
		CloudEvents:     types.CloudEventsOutputConfig{Extensions: make(map[string]string)},
		GCP:             types.GcpOutputConfig{PubSub: types.GcpPubSub{CustomAttributes: make(map[string]string)}},
		OTLP:            types.OTLPOutputConfig{Traces: types.OTLPTraces{ExtraEnvVars: make(map[string]string)}},
	}

	configFile := kingpin.Flag("config-file", "config file").Short('c').ExistingFile()
	version := kingpin.Flag("version", "falcosidekick version").Short('v').Bool()
	kingpin.Parse()

	if *version {
		v := GetVersionInfo()
		fmt.Println(v.String())
		os.Exit(0)
	}

	v := viper.New()
	v.SetDefault("ListenAddress", "")
	v.SetDefault("ListenPort", 2801)
	v.SetDefault("Debug", false)
	v.SetDefault("BracketReplacer", "")
	v.SetDefault("MutualTlsFilesPath", "/etc/certs")
	v.SetDefault("MutualTLSClient.CertFile", "")
	v.SetDefault("MutualTLSClient.KeyFile", "")
	v.SetDefault("MutualTLSClient.CaCertFile", "")
	v.SetDefault("TLSClient.CaCertFile", "")
	v.SetDefault("OutputFieldFormat", "")

	v.SetDefault("TLSServer.Deploy", false)
	v.SetDefault("TLSServer.CertFile", "/etc/certs/server/server.crt")
	v.SetDefault("TLSServer.KeyFile", "/etc/certs/server/server.key")
	v.SetDefault("TLSServer.MutualTLS", false)
	v.SetDefault("TLSServer.CaCertFile", "/etc/certs/server/ca.crt")
	v.SetDefault("TLSServer.NoTLSPort", 2810)

	v.SetDefault("Slack.WebhookURL", "")
	v.SetDefault("Slack.Footer", "https://github.com/falcosecurity/falcosidekick")
	v.SetDefault("Slack.Username", "Falcosidekick")
	v.SetDefault("Slack.Channel", "")
	v.SetDefault("Slack.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Slack.OutputFormat", "all")
	v.SetDefault("Slack.MessageFormat", "")
	v.SetDefault("Slack.MinimumPriority", "")
	v.SetDefault("Slack.MutualTLS", false)
	v.SetDefault("Slack.CheckCert", true)

	v.SetDefault("Rocketchat.WebhookURL", "")
	v.SetDefault("Rocketchat.Footer", "https://github.com/falcosecurity/falcosidekick")
	v.SetDefault("Rocketchat.Username", "Falcosidekick")
	v.SetDefault("Rocketchat.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Rocketchat.OutputFormat", "all")
	v.SetDefault("Rocketchat.MessageFormat", "")
	v.SetDefault("Rocketchat.MinimumPriority", "")
	v.SetDefault("Rocketchat.MutualTLS", false)
	v.SetDefault("Rocketchat.CheckCert", true)

	v.SetDefault("Mattermost.WebhookURL", "")
	v.SetDefault("Mattermost.Footer", "https://github.com/falcosecurity/falcosidekick")
	v.SetDefault("Mattermost.Username", "Falcosidekick")
	v.SetDefault("Mattermost.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Mattermost.OutputFormat", "all")
	v.SetDefault("Mattermost.MessageFormat", "")
	v.SetDefault("Mattermost.MinimumPriority", "")
	v.SetDefault("Mattermost.MutualTLS", false)
	v.SetDefault("Mattermost.CheckCert", true)

	v.SetDefault("Teams.WebhookURL", "")
	v.SetDefault("Teams.ActivityImage", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Teams.OutputFormat", "all")
	v.SetDefault("Teams.MinimumPriority", "")
	v.SetDefault("Teams.MutualTLS", false)
	v.SetDefault("Teams.CheckCert", true)

	v.SetDefault("Datadog.APIKey", "")
	v.SetDefault("Datadog.Host", "https://api.datadoghq.com")
	v.SetDefault("Datadog.MinimumPriority", "")
	v.SetDefault("Datadog.MutualTLS", false)
	v.SetDefault("Datadog.CheckCert", true)

	v.SetDefault("Discord.WebhookURL", "")
	v.SetDefault("Discord.MinimumPriority", "")
	v.SetDefault("Discord.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Discord.MutualTLS", false)
	v.SetDefault("Discord.CheckCert", true)

	v.SetDefault("Alertmanager.HostPort", "")
	v.SetDefault("Alertmanager.MinimumPriority", "")
	v.SetDefault("Alertmanager.MutualTls", false)
	v.SetDefault("Alertmanager.CheckCert", true)
	v.SetDefault("Alertmanager.Endpoint", "/api/v1/alerts")
	v.SetDefault("Alertmanager.ExpiresAfter", 0)
	v.SetDefault("Alertmanager.DropEventDefaultPriority", "critical")
	v.SetDefault("Alertmanager.DropEventThresholds", "10000:critical, 1000:critical, 100:critical, 10:warning, 1:warning")

	v.SetDefault("Elasticsearch.HostPort", "")
	v.SetDefault("Elasticsearch.Index", "falco")
	v.SetDefault("Elasticsearch.Type", "_doc")
	v.SetDefault("Elasticsearch.MinimumPriority", "")
	v.SetDefault("Elasticsearch.Suffix", "daily")
	v.SetDefault("Elasticsearch.MutualTls", false)
	v.SetDefault("Elasticsearch.CheckCert", true)
	v.SetDefault("Elasticsearch.Username", "")
	v.SetDefault("Elasticsearch.Password", "")

	v.SetDefault("Quickwit.HostPort", "")
	v.SetDefault("Quickwit.Index", "falco")
	v.SetDefault("Quickwit.ApiEndpoint", "api/v1")
	v.SetDefault("Quickwit.Version", "0.7")
	v.SetDefault("Quickwit.AutoCreateIndex", false)
	v.SetDefault("Quickwit.MinimumPriority", "")
	v.SetDefault("Quickwit.MutualTls", false)
	v.SetDefault("Quickwit.CheckCert", true)

	v.SetDefault("Influxdb.HostPort", "")
	v.SetDefault("Influxdb.Database", "falco")
	v.SetDefault("Influxdb.Organization", "")
	v.SetDefault("Influxdb.Bucket", "falco")
	v.SetDefault("Influxdb.Precision", "ns")
	v.SetDefault("Influxdb.User", "")
	v.SetDefault("Influxdb.Password", "")
	v.SetDefault("Influxdb.Token", "")
	v.SetDefault("Influxdb.MinimumPriority", "")
	v.SetDefault("Influxdb.MutualTls", false)
	v.SetDefault("Influxdb.CheckCert", true)

	v.SetDefault("Loki.HostPort", "")
	v.SetDefault("Loki.User", "")
	v.SetDefault("Loki.APIKey", "")
	v.SetDefault("Loki.MinimumPriority", "")
	v.SetDefault("Loki.MutualTLS", false)
	v.SetDefault("Loki.CheckCert", true)
	v.SetDefault("Loki.Tenant", "")
	v.SetDefault("Loki.Endpoint", "/loki/api/v1/push")
	v.SetDefault("Loki.ExtraLabels", "")

	v.SetDefault("SumoLogic.MinimumPriority", "")
	v.SetDefault("SumoLogic.ReceiverURL", "")
	v.SetDefault("SumoLogic.SourceCategory", "")
	v.SetDefault("SumoLogic.SourceHost", "")
	v.SetDefault("SumoLogic.Name", "")
	v.SetDefault("SumoLogic.CheckCert", true)
	v.SetDefault("SumoLogic.MutualTLS", false)

	v.SetDefault("AWS.AccessKeyID", "")
	v.SetDefault("AWS.SecretAccessKey", "")
	v.SetDefault("AWS.Region", "")
	v.SetDefault("AWS.RoleARN", "")
	v.SetDefault("AWS.ExternalID", "")
	v.SetDefault("AWS.CheckIdentity", true)

	v.SetDefault("AWS.Lambda.FunctionName", "")
	v.SetDefault("AWS.Lambda.InvocationType", "RequestResponse")
	v.SetDefault("AWS.Lambda.Logtype", "Tail")
	v.SetDefault("AWS.Lambda.MinimumPriority", "")

	v.SetDefault("AWS.SQS.URL", "")
	v.SetDefault("AWS.SQS.MinimumPriority", "")

	v.SetDefault("AWS.SNS.TopicArn", "")
	v.SetDefault("AWS.SNS.MinimumPriority", "")
	v.SetDefault("AWS.SNS.RawJSON", false)

	v.SetDefault("AWS.CloudWatchLogs.LogGroup", "")
	v.SetDefault("AWS.CloudWatchLogs.LogStream", "")
	v.SetDefault("AWS.CloudWatchLogs.MinimumPriority", "")

	v.SetDefault("AWS.S3.Bucket", "")
	v.SetDefault("AWS.S3.Prefix", "falco")
	v.SetDefault("AWS.S3.MinimumPriority", "")
	v.SetDefault("AWS.S3.Endpoint", "")
	v.SetDefault("AWS.S3.ObjectCannedACL", "bucket-owner-full-control")

	v.SetDefault("AWS.SecurityLake.Bucket", "")
	v.SetDefault("AWS.SecurityLake.Region", "")
	v.SetDefault("AWS.SecurityLake.Prefix", "")
	v.SetDefault("AWS.SecurityLake.Interval", 5)
	v.SetDefault("AWS.SecurityLake.BatchSize", 1000)
	v.SetDefault("AWS.SecurityLake.AccountID", "")
	v.SetDefault("AWS.SecurityLake.MinimumPriority", "")

	v.SetDefault("AWS.Kinesis.StreamName", "")
	v.SetDefault("AWS.Kinesis.MinimumPriority", "")

	v.SetDefault("SMTP.HostPort", "")
	v.SetDefault("SMTP.Tls", true)
	v.SetDefault("SMTP.From", "")
	v.SetDefault("SMTP.To", "")
	v.SetDefault("SMTP.OutputFormat", "html")
	v.SetDefault("SMTP.MinimumPriority", "")
	v.SetDefault("SMTP.AuthMechanism", "plain")
	v.SetDefault("SMTP.User", "")
	v.SetDefault("SMTP.Password", "")
	v.SetDefault("SMTP.Token", "")
	v.SetDefault("SMTP.Identity", "")
	v.SetDefault("SMTP.Trace", "")

	v.SetDefault("STAN.HostPort", "")
	v.SetDefault("STAN.ClusterID", "")
	v.SetDefault("STAN.ClientID", "")
	v.SetDefault("STAN.MutualTls", false)
	v.SetDefault("STAN.CheckCert", true)

	v.SetDefault("NATS.HostPort", "")
	v.SetDefault("NATS.ClusterID", "")
	v.SetDefault("NATS.ClientID", "")
	v.SetDefault("NATS.MutualTls", false)
	v.SetDefault("NATS.CheckCert", true)

	v.SetDefault("Opsgenie.Region", "us")
	v.SetDefault("Opsgenie.APIKey", "")
	v.SetDefault("Opsgenie.MinimumPriority", "")
	v.SetDefault("Opsgenie.MutualTLS", false)
	v.SetDefault("Opsgenie.CheckCert", true)

	v.SetDefault("Statsd.Forwarder", "")
	v.SetDefault("Statsd.Namespace", "falcosidekick.")

	v.SetDefault("Prometheus.ExtraLabels", "")

	v.SetDefault("Dogstatsd.Forwarder", "")
	v.SetDefault("Dogstatsd.Namespace", "falcosidekick.")
	v.SetDefault("Dogstatsd.Tags", []string{})

	v.SetDefault("Webhook.Address", "")
	v.SetDefault("Webhook.Method", "POST")
	v.SetDefault("Webhook.MinimumPriority", "")
	v.SetDefault("Webhook.MutualTls", false)
	v.SetDefault("Webhook.CheckCert", true)

	v.SetDefault("NodeRed.Address", "")
	v.SetDefault("NodeRed.User", "")
	v.SetDefault("NodeRed.Password", "")
	v.SetDefault("NodeRed.MinimumPriority", "")
	v.SetDefault("NodeRed.CheckCert", true)

	v.SetDefault("CloudEvents.Address", "")
	v.SetDefault("CloudEvents.MinimumPriority", "")
	v.SetDefault("CloudEvents.MutualTls", false)
	v.SetDefault("CloudEvents.CheckCert", true)

	v.SetDefault("Azure.eventHub.Namespace", "")
	v.SetDefault("Azure.eventHub.Name", "")
	v.SetDefault("Azure.eventHub.MinimumPriority", "")

	v.SetDefault("GCP.Credentials", "")

	v.SetDefault("GCP.PubSub.ProjectID", "")
	v.SetDefault("GCP.PubSub.Topic", "")
	v.SetDefault("GCP.PubSub.MinimumPriority", "")

	v.SetDefault("GCP.Storage.Prefix", "")
	v.SetDefault("GCP.Storage.Bucket", "")
	v.SetDefault("GCP.Storage.MinimumPriority", "")

	v.SetDefault("GCP.CloudFunctions.Name", "")
	v.SetDefault("GCP.CloudFunctions.MinimumPriority", "")

	v.SetDefault("GCP.CloudRun.Endpoint", "")
	v.SetDefault("GCP.CloudRun.JWT", "")
	v.SetDefault("GCP.CloudRun.MinimumPriority", "")

	v.SetDefault("Googlechat.WebhookURL", "")
	v.SetDefault("Googlechat.OutputFormat", "all")
	v.SetDefault("Googlechat.MessageFormat", "")
	v.SetDefault("Googlechat.MinimumPriority", "")
	v.SetDefault("Googlechat.MutualTls", false)
	v.SetDefault("Googlechat.CheckCert", true)

	v.SetDefault("Cliq.WebhookURL", "")
	v.SetDefault("Cliq.Icon", "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png")
	v.SetDefault("Cliq.OutputFormat", "all")
	v.SetDefault("Cliq.UseEmoji", false)
	v.SetDefault("Cliq.MessageFormat", "")
	v.SetDefault("Cliq.MinimumPriority", "")
	v.SetDefault("Cliq.MutualTls", false)
	v.SetDefault("Cliq.CheckCert", true)

	v.SetDefault("Kafka.HostPort", "")
	v.SetDefault("Kafka.Topic", "")
	v.SetDefault("Kafka.MinimumPriority", "")
	v.SetDefault("Kafka.SASL", "")
	v.SetDefault("Kafka.TLS", false)
	v.SetDefault("Kafka.Username", "")
	v.SetDefault("Kafka.Password", "")
	v.SetDefault("Kafka.Balancer", "round_robin")
	v.SetDefault("Kafka.ClientID", "")
	v.SetDefault("Kafka.Compression", "NONE")
	v.SetDefault("Kafka.Async", false)
	v.SetDefault("Kafka.RequiredACKs", "NONE")
	v.SetDefault("Kafka.TopicCreation", false)

	v.SetDefault("KafkaRest.Address", "")
	v.SetDefault("KafkaRest.Version", 2)
	v.SetDefault("KafkaRest.MinimumPriority", "")
	v.SetDefault("KafkaRest.MutualTls", false)
	v.SetDefault("KafkaRest.CheckCert", true)

	v.SetDefault("Pagerduty.RoutingKey", "")
	v.SetDefault("Pagerduty.Region", "us")
	v.SetDefault("Pagerduty.MinimumPriority", "")
	v.SetDefault("Pagerduty.MutualTls", false)
	v.SetDefault("Pagerduty.CheckCert", true)

	v.SetDefault("Kubeless.Namespace", "")
	v.SetDefault("Kubeless.Function", "")
	v.SetDefault("Kubeless.Port", 8080)
	v.SetDefault("Kubeless.Kubeconfig", "")
	v.SetDefault("Kubeless.MinimumPriority", "")
	v.SetDefault("Kubeless.MutualTls", false)
	v.SetDefault("Kubeless.CheckCert", true)

	v.SetDefault("Openfaas.GatewayNamespace", "openfaas")
	v.SetDefault("Openfaas.GatewayService", "gateway")
	v.SetDefault("Openfaas.FunctionName", "")
	v.SetDefault("Openfaas.FunctionNamespace", "openfaas-fn")
	v.SetDefault("Openfaas.GatewayPort", 8080)
	v.SetDefault("Openfaas.Kubeconfig", "")
	v.SetDefault("Openfaas.MinimumPriority", "")
	v.SetDefault("Openfaas.MutualTls", false)
	v.SetDefault("Openfaas.CheckCert", true)

	v.SetDefault("Fission.RouterNamespace", "fission")
	v.SetDefault("Fission.RouterService", "router")
	v.SetDefault("Fission.RouterPort", 80)
	v.SetDefault("Fission.FunctionNamespace", "fission-function")
	v.SetDefault("Fission.Function", "")
	v.SetDefault("Fission.Kubeconfig", "")
	v.SetDefault("Fission.MinimumPriority", "")
	v.SetDefault("Fission.MutualTls", false)
	v.SetDefault("Fission.CheckCert", true)

	v.SetDefault("Webui.URL", "")
	v.SetDefault("Webui.MutualTls", false)
	v.SetDefault("Webui.CheckCert", true)

	v.SetDefault("PolicyReport.Enabled", false)
	v.SetDefault("PolicyReport.Kubeconfig", "")
	v.SetDefault("PolicyReport.MinimumPriority", "")
	v.SetDefault("PolicyReport.MaxEvents", 1000)
	v.SetDefault("PolicyReport.PruneByPriority", false)

	v.SetDefault("Rabbitmq.URL", "")
	v.SetDefault("Rabbitmq.Queue", "")
	v.SetDefault("Rabbitmq.MinimumPriority", "")

	v.SetDefault("Wavefront.EndpointType", "")
	v.SetDefault("Wavefront.EndpointHost", "")
	v.SetDefault("Wavefront.EndpointToken", "")
	v.SetDefault("Wavefront.MetricName", "falco.alert")
	v.SetDefault("Wavefront.EndpointMetricPort", 2878)
	v.SetDefault("Wavefront.MinimumPriority", "")
	v.SetDefault("Wavefront.FlushIntervalSecods", 1)
	v.SetDefault("Wavefront.BatchSize", 10000)

	v.SetDefault("Grafana.HostPort", "")
	v.SetDefault("Grafana.DashboardID", 0)
	v.SetDefault("Grafana.PanelID", 0)
	v.SetDefault("Grafana.APIKey", "")
	v.SetDefault("Grafana.AllFieldsAsTags", false)
	v.SetDefault("Grafana.MinimumPriority", "")
	v.SetDefault("Grafana.MutualTls", false)
	v.SetDefault("Grafana.CheckCert", true)

	v.SetDefault("GrafanaOnCall.WebhookURL", "")
	v.SetDefault("GrafanaOnCall.MinimumPriority", "")
	v.SetDefault("GrafanaOnCall.MutualTls", false)
	v.SetDefault("GrafanaOnCall.CheckCert", true)

	v.SetDefault("Grafana.MinimumPriority", "")
	v.SetDefault("Grafana.MutualTls", false)
	v.SetDefault("Grafana.CheckCert", true)

	v.SetDefault("Yandex.AccessKeyID", "")
	v.SetDefault("Yandex.SecretAccessKey", "")
	v.SetDefault("Yandex.Region", "ru-central1")

	v.SetDefault("Yandex.S3.Endpoint", "https://storage.yandexcloud.net")
	v.SetDefault("Yandex.S3.Bucket", "")
	v.SetDefault("Yandex.S3.Prefix", "falco")
	v.SetDefault("Yamdex.S3.MinimumPriority", "")

	v.SetDefault("Yandex.DataStreams.Endpoint", "https://yds.serverless.yandexcloud.net")
	v.SetDefault("Yandex.DataStreams.StreamName", "")
	v.SetDefault("Yandex.DataStreams.MinimumPriority", "")

	v.SetDefault("Syslog.Host", "")
	v.SetDefault("Syslog.Port", "")
	v.SetDefault("Syslog.Protocol", "")
	v.SetDefault("Syslog.Format", "json")
	v.SetDefault("Syslog.MinimumPriority", "")

	v.SetDefault("MQTT.Broker", "")
	v.SetDefault("MQTT.Topic", "falco/events")
	v.SetDefault("MQTT.QOS", 0)
	v.SetDefault("MQTT.Retained", false)
	v.SetDefault("MQTT.User", "")
	v.SetDefault("MQTT.Password", "")
	v.SetDefault("MQTT.CheckCert", true)
	v.SetDefault("MQTT.MinimumPriority", "")

	v.SetDefault("Zincsearch.HostPort", "")
	v.SetDefault("Zincsearch.Index", "falco")
	v.SetDefault("Zincsearch.Username", "")
	v.SetDefault("Zincsearch.Password", "")
	v.SetDefault("Zincsearch.CheckCert", true)
	v.SetDefault("Zincsearch.MinimumPriority", "")

	v.SetDefault("Gotify.HostPort", "")
	v.SetDefault("Gotify.Token", "")
	v.SetDefault("Gotify.Format", "markdown")
	v.SetDefault("Gotify.CheckCert", true)
	v.SetDefault("Gotify.MinimumPriority", "")

	v.SetDefault("Tekton.EventListener", "")
	v.SetDefault("Tekton.MinimumPriority", "")
	v.SetDefault("Tekton.CheckCert", true)

	v.SetDefault("Spyderbat.OrgUID", "")
	v.SetDefault("Spyderbat.APIKey", "")
	v.SetDefault("Spyderbat.APIUrl", "https://api.spyderbat.com")
	v.SetDefault("Spyderbat.Source", "falcosidekick")
	v.SetDefault("Spyderbat.SourceDescription", "")
	v.SetDefault("Spyderbat.MinimumPriority", "")

	v.SetDefault("TimescaleDB.Host", "")
	v.SetDefault("TimescaleDB.Port", "5432")
	v.SetDefault("TimescaleDB.User", "postgres")
	v.SetDefault("TimescaleDB.Password", "postgres")
	v.SetDefault("TimescaleDB.Database", "falcosidekick")
	v.SetDefault("TimescaleDB.HypertableName", "falcosidekick_events")
	v.SetDefault("TimescaleDB.MinimumPriority", "")

	v.SetDefault("Redis.Address", "")
	v.SetDefault("Redis.Password", "")
	v.SetDefault("Redis.Database", 0)
	v.SetDefault("Redis.StorageType", "list")
	v.SetDefault("Redis.Key", "falco")
	v.SetDefault("Redis.MinimumPriority", "")
	v.SetDefault("Redis.MutualTls", false)
	v.SetDefault("Redis.CheckCert", true)

	v.SetDefault("N8n.Address", "")
	v.SetDefault("N8n.User", "")
	v.SetDefault("N8n.Password", "")
	v.SetDefault("N8n.HeaderAuthName", "")
	v.SetDefault("N8n.HeaderAuthValue", "")
	v.SetDefault("N8n.MinimumPriority", "")
	v.SetDefault("N8n.CheckCert", true)

	v.SetDefault("Telegram.Token", "")
	v.SetDefault("Telegram.ChatID", "")
	v.SetDefault("Telegram.MinimumPriority", "")
	v.SetDefault("Telegram.CheckCert", true)

	v.SetDefault("OpenObserve.HostPort", "")
	v.SetDefault("OpenObserve.OrganizationName", "default")
	v.SetDefault("OpenObserve.StreamName", "falco")
	v.SetDefault("OpenObserve.MinimumPriority", "")
	v.SetDefault("OpenObserve.MutualTls", false)
	v.SetDefault("OpenObserve.CheckCert", true)
	v.SetDefault("OpenObserve.Username", "")
	v.SetDefault("OpenObserve.Password", "")

	v.SetDefault("Dynatrace.APIToken", "")
	v.SetDefault("Dynatrace.APIUrl", "")
	v.SetDefault("Dynatrace.CheckCert", true)
	v.SetDefault("Dynatrace.MinimumPriority", "")

	v.SetDefault("OTLP.Traces.Endpoint", "")
	v.SetDefault("OTLP.Traces.Protocol", "http/json")
	// NOTE: we don't need to parse the OTLP.Traces.Headers field, as use it to
	// set OTEL_EXPORTER_OTLP_TRACES_HEADERS (at otlp_init.go), which is then
	// parsed by the OTLP SDK libs, see
	// https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/#otel_exporter_otlp_traces_headers
	v.SetDefault("OTLP.Traces.Headers", "")
	v.SetDefault("OTLP.Traces.Timeout", 10000)
	v.SetDefault("OTLP.Traces.Synced", false)
	v.SetDefault("OTLP.Traces.MinimumPriority", "")
	v.SetDefault("OTLP.Traces.CheckCert", true)
	// NB: Unfortunately falco events don't provide endtime, artificially set
	// it to 1000ms by default, override-able via OTLP_DURATION environment variable.
	v.SetDefault("OTLP.Traces.Duration", 1000)

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if *configFile != "" {
		d, f := path.Split(*configFile)
		if d == "" {
			d = "."
		}
		v.SetConfigName(f[0 : len(f)-len(filepath.Ext(f))])
		v.AddConfigPath(d)
		err := v.ReadInConfig()
		if err != nil {
			log.Printf("[ERROR] : Error when reading config file : %v\n", err)
		}
	}

	v.GetStringSlice("TLSServer.NoTLSPaths")

	v.GetStringMapString("Customfields")
	v.GetStringMapString("Templatedfields")
	v.GetStringMapString("Webhook.CustomHeaders")
	v.GetStringMapString("CloudEvents.Extensions")
	v.GetStringMapString("AlertManager.ExtraLabels")
	v.GetStringMapString("AlertManager.ExtraAnnotations")
	v.GetStringMapString("AlertManager.CustomSeverityMap")
	v.GetStringMapString("GCP.PubSub.CustomAttributes")
	v.GetStringMapString("OTLP.Traces.ExtraEnvVars")
	if err := v.Unmarshal(c); err != nil {
		log.Printf("[ERROR] : Error unmarshalling config : %s", err)
	}

	if value, present := os.LookupEnv("TLSSERVER_NOTLSPATHS"); present {
		c.TLSServer.NoTLSPaths = strings.Split(value, ",")
	}

	if value, present := os.LookupEnv("CUSTOMFIELDS"); present {
		customfields := strings.Split(value, ",")
		for _, label := range customfields {
			tagkeys := strings.Split(label, ":")
			if len(tagkeys) == 2 {
				if strings.HasPrefix(tagkeys[1], "%") {
					if s := os.Getenv(tagkeys[1][1:]); s != "" {
						c.Customfields[tagkeys[0]] = s
					} else {
						log.Printf("[ERROR] : Can't find env var %v for custom fields", tagkeys[1][1:])
					}
				} else {
					c.Customfields[tagkeys[0]] = tagkeys[1]
				}
			}
		}
	}

	if value, present := os.LookupEnv("TEMPLATEDFIELDS"); present {
		templatedfields := strings.Split(value, ",")
		for _, label := range templatedfields {
			tagkeys := strings.Split(label, ":")
			if len(tagkeys) == 2 {
				if _, err := template.New("").Parse(tagkeys[1]); err != nil {
					log.Printf("[ERROR] : Error parsing templated fields %v : %s", tagkeys[0], err)
				} else {
					c.Templatedfields[tagkeys[0]] = tagkeys[1]
				}
			}
		}
	}

	if value, present := os.LookupEnv("WEBHOOK_CUSTOMHEADERS"); present {
		customheaders := strings.Split(value, ",")
		for _, label := range customheaders {
			tagkeys := strings.Split(label, ":")
			if len(tagkeys) == 2 {
				c.Webhook.CustomHeaders[tagkeys[0]] = tagkeys[1]
			}
		}
	}

	if value, present := os.LookupEnv("CLOUDEVENTS_EXTENSIONS"); present {
		extensions := strings.Split(value, ",")
		for _, label := range extensions {
			tagkeys := strings.Split(label, ":")
			if len(tagkeys) == 2 {
				c.CloudEvents.Extensions[tagkeys[0]] = tagkeys[1]
			}
		}
	}

	promKVNameRegex, _ := regexp.Compile("^[a-zA-Z_][a-zA-Z0-9_]*$")

	if value, present := os.LookupEnv("ALERTMANAGER_EXTRALABELS"); present {
		extraLabels := strings.Split(value, ",")
		for _, labelData := range extraLabels {
			labelName, labelValue, found := strings.Cut(labelData, ":")
			labelName, labelValue = strings.TrimSpace(labelName), strings.TrimSpace(labelValue)
			if !promKVNameRegex.MatchString(labelName) {
				log.Printf("[ERROR] : AlertManager - Extra label name '%v' is not valid", labelName)
			} else if found {
				c.Alertmanager.ExtraLabels[labelName] = labelValue
			} else {
				c.Alertmanager.ExtraLabels[labelName] = ""
			}
		}
	}

	if value, present := os.LookupEnv("ALERTMANAGER_EXTRAANNOTATIONS"); present {
		extraAnnotations := strings.Split(value, ",")
		for _, annotationData := range extraAnnotations {
			annotationName, annotationValue, found := strings.Cut(annotationData, ":")
			annotationName, annotationValue = strings.TrimSpace(annotationName), strings.TrimSpace(annotationValue)
			if !promKVNameRegex.MatchString(annotationName) {
				log.Printf("[ERROR] : AlertManager - Extra annotation name '%v' is not valid", annotationName)
			} else if found {
				c.Alertmanager.ExtraAnnotations[annotationName] = annotationValue
			} else {
				c.Alertmanager.ExtraAnnotations[annotationName] = ""
			}
		}
	}

	if value, present := os.LookupEnv("ALERTMANAGER_CUSTOMSEVERITYMAP"); present {
		severitymap := strings.Split(value, ",")
		for _, severitymatch := range severitymap {
			priorityString, severityValue, found := strings.Cut(severitymatch, ":")
			priority := types.Priority(priorityString)
			if priority == types.Default {
				log.Printf("[ERROR] : AlertManager - Priority '%v' is not a valid falco priority level", priorityString)
				continue
			} else if found {
				c.Alertmanager.CustomSeverityMap[priority] = strings.TrimSpace(severityValue)
			} else {
				log.Printf("[ERROR] : AlertManager - No severity given to '%v' (tuple extracted: '%v')", priorityString, severitymatch)
			}
		}
	}

	if value, present := os.LookupEnv("ALERTMANAGER_DROPEVENTTHRESHOLDS"); present {
		c.Alertmanager.DropEventThresholds = value
	}

	if value, present := os.LookupEnv("ALERTMANAGER_CUSTOMHEADERS"); present {
		customheaders := strings.Split(value, ",")
		for _, label := range customheaders {
			tagkeys := strings.Split(label, ":")
			if len(tagkeys) == 2 {
				c.Alertmanager.CustomHeaders[tagkeys[0]] = tagkeys[1]
			}
		}
	}

	if value, present := os.LookupEnv("GCP_PUBSUB_CUSTOMATTRIBUTES"); present {
		customattributes := strings.Split(value, ",")
		for _, label := range customattributes {
			tagkeys := strings.Split(label, ":")
			if len(tagkeys) == 2 {
				c.GCP.PubSub.CustomAttributes[tagkeys[0]] = tagkeys[1]
			}
		}
	}

	if value, present := os.LookupEnv("OTLP_TRACES_EXTRAENVVARS"); present {
		extraEnvVars := strings.Split(value, ",")
		for _, extraEnvVarData := range extraEnvVars {
			envName, envValue, found := strings.Cut(extraEnvVarData, ":")
			envName, envValue = strings.TrimSpace(envName), strings.TrimSpace(envValue)
			if !promKVNameRegex.MatchString(envName) {
				log.Printf("[ERROR] : OTLPTraces - Extra Env Var name '%v' is not valid", envName)
			} else if found {
				c.OTLP.Traces.ExtraEnvVars[envName] = envValue
			} else {
				c.OTLP.Traces.ExtraEnvVars[envName] = ""
			}
		}
	}

	if c.AWS.SecurityLake.Interval < 5 {
		c.AWS.SecurityLake.Interval = 5
	}
	if c.AWS.SecurityLake.Interval > 60 {
		c.AWS.SecurityLake.Interval = 60
	}

	if c.ListenPort == 0 || c.ListenPort > 65536 {
		log.Fatalf("[ERROR] : Bad listening port number\n")
	}

	if c.TLSServer.NoTLSPort == 0 || c.TLSServer.NoTLSPort > 65536 {
		log.Fatalf("[ERROR] : Bad noTLS server port number\n")
	}

	if ip := net.ParseIP(c.ListenAddress); c.ListenAddress != "" && ip == nil {
		log.Fatalf("[ERROR] : Failed to parse ListenAddress")
	}

	if c.Loki.ExtraLabels != "" {
		c.Loki.ExtraLabelsList = strings.Split(strings.ReplaceAll(c.Loki.ExtraLabels, " ", ""), ",")
	}

	if c.Prometheus.ExtraLabels != "" {
		c.Prometheus.ExtraLabelsList = strings.Split(strings.ReplaceAll(c.Prometheus.ExtraLabels, " ", ""), ",")
	}

	if c.Alertmanager.DropEventThresholds != "" {
		c.Alertmanager.DropEventThresholdsList = make([]types.ThresholdConfig, 0)
		thresholds := strings.Split(strings.ReplaceAll(c.Alertmanager.DropEventThresholds, " ", ""), ",")
		for _, threshold := range thresholds {
			values := strings.SplitN(threshold, ":", 2)
			if len(values) != 2 {
				log.Printf("[ERROR] : AlertManager - Fail to parse threshold - No priority given for threshold %v", threshold)
				continue
			}
			valueString := strings.TrimSpace(values[0])
			valueInt, err := strconv.ParseInt(valueString, 10, 64)
			if len(values) != 2 || err != nil {
				log.Printf("[ERROR] : AlertManager - Fail to parse threshold - Atoi fail %v", threshold)
				continue
			}
			priority := types.Priority(strings.TrimSpace(values[1]))
			if priority == types.Default {
				log.Printf("[ERROR] : AlertManager - Priority '%v' is not a valid falco priority level", priority.String())
				continue
			}
			c.Alertmanager.DropEventThresholdsList = append(c.Alertmanager.DropEventThresholdsList, types.ThresholdConfig{Priority: priority, Value: valueInt})
		}
	}

	if len(c.Alertmanager.DropEventThresholdsList) > 0 {
		sort.Slice(c.Alertmanager.DropEventThresholdsList, func(i, j int) bool {
			// The `>` is used to sort in descending order. If you want to sort in ascending order, use `<`.
			return c.Alertmanager.DropEventThresholdsList[i].Value > c.Alertmanager.DropEventThresholdsList[j].Value
		})
	}

	c.Slack.MinimumPriority = checkPriority(c.Slack.MinimumPriority)
	c.Rocketchat.MinimumPriority = checkPriority(c.Rocketchat.MinimumPriority)
	c.Mattermost.MinimumPriority = checkPriority(c.Mattermost.MinimumPriority)
	c.Teams.MinimumPriority = checkPriority(c.Teams.MinimumPriority)
	c.Datadog.MinimumPriority = checkPriority(c.Datadog.MinimumPriority)
	c.Alertmanager.MinimumPriority = checkPriority(c.Alertmanager.MinimumPriority)
	c.Alertmanager.DropEventDefaultPriority = checkPriority(c.Alertmanager.DropEventDefaultPriority)
	c.Elasticsearch.MinimumPriority = checkPriority(c.Elasticsearch.MinimumPriority)
	c.Quickwit.MinimumPriority = checkPriority(c.Quickwit.MinimumPriority)
	c.Influxdb.MinimumPriority = checkPriority(c.Influxdb.MinimumPriority)
	c.Loki.MinimumPriority = checkPriority(c.Loki.MinimumPriority)
	c.SumoLogic.MinimumPriority = checkPriority(c.SumoLogic.MinimumPriority)
	c.Nats.MinimumPriority = checkPriority(c.Nats.MinimumPriority)
	c.Stan.MinimumPriority = checkPriority(c.Stan.MinimumPriority)
	c.AWS.Lambda.MinimumPriority = checkPriority(c.AWS.Lambda.MinimumPriority)
	c.AWS.SQS.MinimumPriority = checkPriority(c.AWS.SQS.MinimumPriority)
	c.AWS.SNS.MinimumPriority = checkPriority(c.AWS.SNS.MinimumPriority)
	c.AWS.S3.MinimumPriority = checkPriority(c.AWS.S3.MinimumPriority)
	c.AWS.SecurityLake.MinimumPriority = checkPriority(c.AWS.SecurityLake.MinimumPriority)
	c.AWS.CloudWatchLogs.MinimumPriority = checkPriority(c.AWS.CloudWatchLogs.MinimumPriority)
	c.AWS.Kinesis.MinimumPriority = checkPriority(c.AWS.Kinesis.MinimumPriority)
	c.Opsgenie.MinimumPriority = checkPriority(c.Opsgenie.MinimumPriority)
	c.Webhook.MinimumPriority = checkPriority(c.Webhook.MinimumPriority)
	c.CloudEvents.MinimumPriority = checkPriority(c.CloudEvents.MinimumPriority)
	c.Azure.EventHub.MinimumPriority = checkPriority(c.Azure.EventHub.MinimumPriority)
	c.GCP.PubSub.MinimumPriority = checkPriority(c.GCP.PubSub.MinimumPriority)
	c.GCP.Storage.MinimumPriority = checkPriority(c.GCP.Storage.MinimumPriority)
	c.GCP.CloudFunctions.MinimumPriority = checkPriority(c.GCP.CloudFunctions.MinimumPriority)
	c.GCP.CloudRun.MinimumPriority = checkPriority(c.GCP.CloudRun.MinimumPriority)
	c.Googlechat.MinimumPriority = checkPriority(c.Googlechat.MinimumPriority)
	c.Cliq.MinimumPriority = checkPriority(c.Cliq.MinimumPriority)
	c.Kafka.MinimumPriority = checkPriority(c.Kafka.MinimumPriority)
	c.KafkaRest.MinimumPriority = checkPriority(c.KafkaRest.MinimumPriority)
	c.Pagerduty.MinimumPriority = checkPriority(c.Pagerduty.MinimumPriority)
	c.Kubeless.MinimumPriority = checkPriority(c.Kubeless.MinimumPriority)
	c.Openfaas.MinimumPriority = checkPriority(c.Openfaas.MinimumPriority)
	c.Tekton.MinimumPriority = checkPriority(c.Tekton.MinimumPriority)
	c.Fission.MinimumPriority = checkPriority(c.Fission.MinimumPriority)
	c.Rabbitmq.MinimumPriority = checkPriority(c.Rabbitmq.MinimumPriority)
	c.Wavefront.MinimumPriority = checkPriority(c.Wavefront.MinimumPriority)
	c.Yandex.S3.MinimumPriority = checkPriority(c.Yandex.S3.MinimumPriority)
	c.Yandex.DataStreams.MinimumPriority = checkPriority(c.Yandex.DataStreams.MinimumPriority)
	c.Syslog.MinimumPriority = checkPriority(c.Syslog.MinimumPriority)
	c.MQTT.MinimumPriority = checkPriority(c.MQTT.MinimumPriority)
	c.PolicyReport.MinimumPriority = checkPriority(c.PolicyReport.MinimumPriority)
	c.Spyderbat.MinimumPriority = checkPriority(c.Spyderbat.MinimumPriority)
	c.Zincsearch.MinimumPriority = checkPriority(c.Zincsearch.MinimumPriority)
	c.NodeRed.MinimumPriority = checkPriority(c.NodeRed.MinimumPriority)
	c.Gotify.MinimumPriority = checkPriority(c.Gotify.MinimumPriority)
	c.TimescaleDB.MinimumPriority = checkPriority(c.TimescaleDB.MinimumPriority)
	c.Redis.MinimumPriority = checkPriority(c.Redis.MinimumPriority)
	c.Telegram.MinimumPriority = checkPriority(c.Telegram.MinimumPriority)
	c.N8N.MinimumPriority = checkPriority(c.N8N.MinimumPriority)
	c.OpenObserve.MinimumPriority = checkPriority(c.OpenObserve.MinimumPriority)
	c.Dynatrace.MinimumPriority = checkPriority(c.Dynatrace.MinimumPriority)

	c.Slack.MessageFormatTemplate = getMessageFormatTemplate("Slack", c.Slack.MessageFormat)
	c.Rocketchat.MessageFormatTemplate = getMessageFormatTemplate("Rocketchat", c.Rocketchat.MessageFormat)
	c.Mattermost.MessageFormatTemplate = getMessageFormatTemplate("Mattermost", c.Mattermost.MessageFormat)
	c.Googlechat.MessageFormatTemplate = getMessageFormatTemplate("Googlechat", c.Googlechat.MessageFormat)
	c.Cliq.MessageFormatTemplate = getMessageFormatTemplate("Cliq", c.Cliq.MessageFormat)

	return c
}

func checkPriority(prio string) string {
	match, _ := regexp.MatchString("(?i)(emergency|alert|critical|error|warning|notice|informational|debug)", prio)
	if match {
		return prio
	}

	return ""
}

func getMessageFormatTemplate(output, temp string) *template.Template {
	if temp != "" {
		var err error
		t, err := template.New(output).Parse(temp)
		if err != nil {
			log.Fatalf("[ERROR] : Error compiling %v message template : %v\n", output, err)
		}
		return t
	}

	return nil
}
