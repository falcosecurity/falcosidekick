package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/spf13/viper"
	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"github.com/falcosecurity/falcosidekick/types"
)

func getConfig() *types.Configuration {
	c := &types.Configuration{
		Customfields: make(map[string]string),
		Webhook:      types.WebhookOutputConfig{CustomHeaders: make(map[string]string)},
		Alertmanager: types.AlertmanagerOutputConfig{ExtraLabels: make(map[string]string), ExtraAnnotations: make(map[string]string)},
		CloudEvents:  types.CloudEventsOutputConfig{Extensions: make(map[string]string)},
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
	v.SetDefault("MutualTlsFilesPath", "/etc/certs")

	v.SetDefault("Slack.WebhookURL", "")
	v.SetDefault("Slack.Footer", "https://github.com/falcosecurity/falcosidekick")
	v.SetDefault("Slack.Username", "Falcosidekick")
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

	v.SetDefault("Elasticsearch.HostPort", "")
	v.SetDefault("Elasticsearch.Index", "falco")
	v.SetDefault("Elasticsearch.Type", "_doc")
	v.SetDefault("Elasticsearch.MinimumPriority", "")
	v.SetDefault("Elasticsearch.Suffix", "daily")
	v.SetDefault("Elasticsearch.MutualTls", false)
	v.SetDefault("Elasticsearch.CheckCert", true)
	v.SetDefault("Elasticsearch.Username", "")
	v.SetDefault("Elasticsearch.Password", "")

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
	v.SetDefault("Loki.MinimumPriority", "")
	v.SetDefault("Loki.MutualTLS", false)
	v.SetDefault("Loki.CheckCert", true)
	v.SetDefault("Loki.Tenant", "")
	v.SetDefault("Loki.Endpoint", "/loki/api/v1/push")
	v.SetDefault("Loki.ExtraLabels", "")

	v.SetDefault("AWS.AccessKeyID", "")
	v.SetDefault("AWS.SecretAccessKey", "")
	v.SetDefault("AWS.Region", "")

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

	v.SetDefault("AWS.Kinesis.StreamName", "")
	v.SetDefault("AWS.Kinesis.MinimumPriority", "")

	v.SetDefault("SMTP.HostPort", "")
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

	v.SetDefault("KafkaRest.Address", "")
	v.SetDefault("KafkaRest.Version", 2)
	v.SetDefault("KafkaRest.MinimumPriority", "")
	v.SetDefault("KafkaRest.MutualTls", false)
	v.SetDefault("KafkaRest.CheckCert", true)

	v.SetDefault("Pagerduty.RoutingKey", "")
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
	v.SetDefault("Syslog.MinimumPriority", "")

	v.SetDefault("MQTT.Broker", "")
	v.SetDefault("MQTT.Topic", "falco/events")
	v.SetDefault("MQTT.QOS", 0)
	v.SetDefault("MQTT.Retained", false)
	v.SetDefault("MQTT.User", "")
	v.SetDefault("MQTT.Password", "")
	v.SetDefault("MQTT.CheckCert", true)
	v.SetDefault("MQTT.MinimumPriority", "")

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

	v.GetStringMapString("Customfields")
	v.GetStringMapString("Webhook.CustomHeaders")
	v.GetStringMapString("CloudEvents.Extensions")
	v.GetStringMapString("AlertManager.ExtraLabels")
	v.GetStringMapString("AlertManager.ExtraAnnotations")
	if err := v.Unmarshal(c); err != nil {
		log.Printf("[ERROR] : Error unmarshalling config : %s", err)
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
	regex, _ := regexp.Compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")
	if value, present := os.LookupEnv("ALERTMANAGER_EXTRALABELS"); present {
		extralabels := strings.Split(value, ",")
		for _, labelData := range extralabels {
			if !regex.MatchString(labelData) {
				log.Printf("[ERROR] : AlertManager - Extra field '%v' is not a valid prometheus labelData", labelData)
				continue
			}
			values := strings.SplitN(labelData, ":", 2)
			label := strings.TrimSpace(values[0])
			if !regex.MatchString(label) {
				log.Printf("[ERROR] : AlertManager - Extra field '%v' is not a valid prometheus label", label)
				continue
			}
			if len(values) == 2 {
				c.Alertmanager.ExtraLabels[label] = strings.TrimSpace(values[1])
			} else {
				c.Alertmanager.ExtraLabels[label] = ""
			}
		}
	}

	if value, present := os.LookupEnv("ALERTMANAGER_EXTRAANNOTATIONS"); present {
		extraannotations := strings.Split(value, ",")
		for _, annotationData := range extraannotations {
			values := strings.SplitN(annotationData, ":", 2)
			annotation := strings.TrimSpace(values[0])
			if !regex.MatchString(annotation) {
				log.Printf("[ERROR] : AlertManager - Extra field '%v' is not a valid prometheus annotation", annotation)
				continue
			}
			if len(values) == 2 {
				c.Alertmanager.ExtraAnnotations[annotation] = strings.TrimSpace(values[1])
			} else {
				c.Alertmanager.ExtraAnnotations[annotation] = ""
			}
		}
	}

	if c.ListenPort == 0 || c.ListenPort > 65536 {
		log.Fatalf("[ERROR] : Bad port number\n")
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

	c.Slack.MinimumPriority = checkPriority(c.Slack.MinimumPriority)
	c.Rocketchat.MinimumPriority = checkPriority(c.Rocketchat.MinimumPriority)
	c.Mattermost.MinimumPriority = checkPriority(c.Mattermost.MinimumPriority)
	c.Teams.MinimumPriority = checkPriority(c.Teams.MinimumPriority)
	c.Datadog.MinimumPriority = checkPriority(c.Datadog.MinimumPriority)
	c.Alertmanager.MinimumPriority = checkPriority(c.Alertmanager.MinimumPriority)
	c.Elasticsearch.MinimumPriority = checkPriority(c.Elasticsearch.MinimumPriority)
	c.Influxdb.MinimumPriority = checkPriority(c.Influxdb.MinimumPriority)
	c.Loki.MinimumPriority = checkPriority(c.Loki.MinimumPriority)
	c.Nats.MinimumPriority = checkPriority(c.Nats.MinimumPriority)
	c.Stan.MinimumPriority = checkPriority(c.Stan.MinimumPriority)
	c.AWS.Lambda.MinimumPriority = checkPriority(c.AWS.Lambda.MinimumPriority)
	c.AWS.SQS.MinimumPriority = checkPriority(c.AWS.SQS.MinimumPriority)
	c.AWS.SNS.MinimumPriority = checkPriority(c.AWS.SNS.MinimumPriority)
	c.AWS.S3.MinimumPriority = checkPriority(c.AWS.S3.MinimumPriority)
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
	c.Fission.MinimumPriority = checkPriority(c.Fission.MinimumPriority)
	c.Rabbitmq.MinimumPriority = checkPriority(c.Rabbitmq.MinimumPriority)
	c.Wavefront.MinimumPriority = checkPriority(c.Wavefront.MinimumPriority)
	c.Yandex.S3.MinimumPriority = checkPriority(c.Yandex.S3.MinimumPriority)
	c.Yandex.DataStreams.MinimumPriority = checkPriority(c.Yandex.DataStreams.MinimumPriority)
	c.Syslog.MinimumPriority = checkPriority(c.Syslog.MinimumPriority)
	c.MQTT.MinimumPriority = checkPriority(c.MQTT.MinimumPriority)
	c.PolicyReport.MinimumPriority = checkPriority(c.PolicyReport.MinimumPriority)

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
