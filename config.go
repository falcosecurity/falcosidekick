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

// Max concurrent requests at a time per output, unlimited if set to 0
// Setting it to 1 by default, because the previously
// many outputs were synchronized on headers locks, in all or some cases
// and that was limiting the the number of requests to 1 at a time.
const defaultMaxConcurrentHttpRequests = 1

// Common http outputs defaults
var commonHttpOutputDefaults = map[string]any{
	"MutualTLS": false,
	"CheckCert": true,
	// Max concurrent requests at a time per http-based output
	"MaxConcurrentRequests": defaultMaxConcurrentHttpRequests,
}

// Http based outputs that share the common http defaults above
var httpOutputDefaults = map[string]map[string]any{
	"Slack": {
		"WebhookURL":      "",
		"Footer":          "https://github.com/falcosecurity/falcosidekick",
		"Username":        "Falcosidekick",
		"Channel":         "",
		"Icon":            "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png",
		"OutputFormat":    "all",
		"MessageFormat":   "",
		"MinimumPriority": "",
	},
	"Rocketchat": {
		"WebhookURL":      "",
		"Footer":          "https://github.com/falcosecurity/falcosidekick",
		"Username":        "Falcosidekick",
		"Icon":            "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png",
		"OutputFormat":    "all",
		"MessageFormat":   "",
		"MinimumPriority": "",
	},
	"Mattermost": {
		"WebhookURL":      "",
		"Footer":          "https://github.com/falcosecurity/falcosidekick",
		"Username":        "Falcosidekick",
		"Icon":            "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png",
		"OutputFormat":    "all",
		"MessageFormat":   "",
		"MinimumPriority": "",
	},
	"Teams": {
		"WebhookURL":      "",
		"ActivityImage":   "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png",
		"OutputFormat":    "all",
		"MinimumPriority": "",
	},
	"Webex": {
		"WebhookURL":      "",
		"MinimumPriority": "",
	},
	"Datadog": {
		"APIKey":          "",
		"Host":            "https://api.datadoghq.com",
		"MinimumPriority": "",
	},
	"Discord": {
		"WebhookURL":      "",
		"MinimumPriority": "",
		"Icon":            "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png",
	},
	"Alertmanager": {
		"HostPort":                 "",
		"MinimumPriority":          "",
		"Endpoint":                 "/api/v1/alerts",
		"ExpiresAfter":             0,
		"DropEventDefaultPriority": "critical",
		"DropEventThresholds":      "10000:critical: 1000:critical: 100:critical: 10:warning: 1:warning",
	},
	"Elasticsearch": {
		"HostPort":            "",
		"Index":               "falco",
		"Type":                "_doc",
		"MinimumPriority":     "",
		"Suffix":              "daily",
		"Username":            "",
		"Password":            "",
		"FlattenFields":       false,
		"CreateIndexTemplate": false,
		"NumberOfShards":      3,
		"NumberOfReplicas":    3,
	},
	"Quickwit": {
		"HostPort":        "",
		"Index":           "falco",
		"ApiEndpoint":     "api/v1",
		"Version":         "0.7",
		"AutoCreateIndex": false,
		"MinimumPriority": "",
	},
	"Influxdb": {
		"HostPort":        "",
		"Database":        "falco",
		"Organization":    "",
		"Bucket":          "falco",
		"Precision":       "ns",
		"User":            "",
		"Password":        "",
		"Token":           "",
		"MinimumPriority": "",
	},
	"Loki": {
		"HostPort":        "",
		"User":            "",
		"APIKey":          "",
		"MinimumPriority": "",
		"Tenant":          "",
		"Endpoint":        "/loki/api/v1/push",
		"ExtraLabels":     "",
	},
	"SumoLogic": {
		"MinimumPriority": "",
		"ReceiverURL":     "",
		"SourceCategory":  "",
		"SourceHost":      "",
		"Name":            "",
	},
	"STAN": {
		"HostPort":  "",
		"ClusterID": "",
		"ClientID":  "",
	},
	"NATS": {
		"HostPort":  "",
		"ClusterID": "",
		"ClientID":  "",
	},
	"Opsgenie": {
		"Region":          "us",
		"APIKey":          "",
		"MinimumPriority": "",
	},
	"Webhook": {
		"Address":         "",
		"Method":          "POST",
		"MinimumPriority": "",
	},
	"CloudEvents": {
		"Address":         "",
		"MinimumPriority": "",
	},
	"Googlechat": {
		"WebhookURL":      "",
		"OutputFormat":    "all",
		"MessageFormat":   "",
		"MinimumPriority": "",
	},
	"Cliq": {
		"WebhookURL":      "",
		"Icon":            "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick_color.png",
		"OutputFormat":    "all",
		"UseEmoji":        false,
		"MessageFormat":   "",
		"MinimumPriority": "",
	},
	"KafkaRest": {
		"Address":         "",
		"Version":         2,
		"MinimumPriority": "",
	},
	"Pagerduty": {
		"RoutingKey":      "",
		"Region":          "us",
		"MinimumPriority": "",
	},
	"Kubeless": {
		"Namespace":       "",
		"Function":        "",
		"Port":            8080,
		"Kubeconfig":      "",
		"MinimumPriority": "",
	},
	"Openfaas": {
		"GatewayNamespace":  "openfaas",
		"GatewayService":    "gateway",
		"FunctionName":      "",
		"FunctionNamespace": "openfaas-fn",
		"GatewayPort":       8080,
		"Kubeconfig":        "",
		"MinimumPriority":   "",
	},
	"Fission": {
		"RouterNamespace":   "fission",
		"RouterService":     "router",
		"RouterPort":        80,
		"FunctionNamespace": "fission-function",
		"Function":          "",
		"Kubeconfig":        "",
		"MinimumPriority":   "",
		"MutualTLS":         false,
		"CheckCert":         true,
	},
	"Webui": {
		"URL": "",
	},
	"Grafana": {
		"HostPort":        "",
		"DashboardID":     0,
		"PanelID":         0,
		"APIKey":          "",
		"AllFieldsAsTags": false,
		"MinimumPriority": "",
	},
	"GrafanaOnCall": {
		"WebhookURL":      "",
		"MinimumPriority": "",
	},
	"Redis": {
		"Address":         "",
		"Password":        "",
		"Database":        0,
		"StorageType":     "list",
		"Key":             "falco",
		"MinimumPriority": "",
	},
	"OpenObserve": {
		"HostPort":         "",
		"OrganizationName": "default",
		"StreamName":       "falco",
		"MinimumPriority":  "",
		"Username":         "",
		"Password":         "",
	},
}

// Other output defaults that do not need commonHttpOutputDefaults
var outputDefaults = map[string]map[string]any{
	"SMTP": {
		"HostPort":        "",
		"Tls":             true,
		"From":            "",
		"To":              "",
		"OutputFormat":    "html",
		"MinimumPriority": "",
		"AuthMechanism":   "plain",
		"User":            "",
		"Password":        "",
		"Token":           "",
		"Identity":        "",
		"Trace":           "",
	},
	"Statsd": {
		"Forwarder": "",
		"Namespace": "falcosidekick.",
	},
	"Dogstatsd": {
		"Forwarder": "",
		"Namespace": "falcosidekick.",
		"Tags":      []string{},
	},
	"NodeRed": {
		"Address":         "",
		"User":            "",
		"Password":        "",
		"MinimumPriority": "",
		"CheckCert":       true,
	},
	"Kafka": {
		"HostPort":        "",
		"Topic":           "",
		"MinimumPriority": "",
		"SASL":            "",
		"TLS":             false,
		"Username":        "",
		"Password":        "",
		"Balancer":        "round_robin",
		"ClientID":        "",
		"Compression":     "NONE",
		"Async":           false,
		"RequiredACKs":    "NONE",
		"TopicCreation":   false,
	},
	"PolicyReport": {
		"Enabled":         false,
		"Kubeconfig":      "",
		"MinimumPriority": "",
		"MaxEvents":       1000,
		"FalcoNamespace":  "",
		"PruneByPriority": false,
	},
	"Rabbitmq": {
		"URL":             "",
		"Queue":           "",
		"MinimumPriority": "",
	},
	"Wavefront": {
		"EndpointType":        "",
		"EndpointHost":        "",
		"EndpointToken":       "",
		"MetricName":          "falco.alert",
		"EndpointMetricPort":  2878,
		"MinimumPriority":     "",
		"FlushIntervalSecods": 1,
		"BatchSize":           10000,
	},
	"Syslog": {
		"Host":            "",
		"Port":            "",
		"Protocol":        "",
		"Format":          "json",
		"MinimumPriority": "",
	},
	"MQTT": {
		"Broker":          "",
		"Topic":           "falco/events",
		"QOS":             0,
		"Retained":        false,
		"User":            "",
		"Password":        "",
		"CheckCert":       true,
		"MinimumPriority": "",
	},
	"Zincsearch": {
		"HostPort":        "",
		"Index":           "falco",
		"Username":        "",
		"Password":        "",
		"CheckCert":       true,
		"MinimumPriority": "",
	},
	"Gotify": {
		"HostPort":        "",
		"Token":           "",
		"Format":          "markdown",
		"CheckCert":       true,
		"MinimumPriority": "",
	},
	"Tekton": {
		"EventListener":   "",
		"MinimumPriority": "",
		"CheckCert":       true,
	},
	"Spyderbat": {
		"OrgUID":            "",
		"APIKey":            "",
		"APIUrl":            "https://api.spyderbat.com",
		"Source":            "falcosidekick",
		"SourceDescription": "",
		"MinimumPriority":   "",
	},
	"TimescaleDB": {
		"Host":            "",
		"Port":            "5432",
		"User":            "postgres",
		"Password":        "postgres",
		"Database":        "falcosidekick",
		"HypertableName":  "falcosidekick_events",
		"MinimumPriority": "",
	},
	"N8n": {
		"Address":         "",
		"User":            "",
		"Password":        "",
		"HeaderAuthName":  "",
		"HeaderAuthValue": "",
		"MinimumPriority": "",
		"CheckCert":       true,
	},
	"Telegram": {
		"Token":           "",
		"ChatID":          "",
		"MinimumPriority": "",
		"CheckCert":       true,
	},
	"Dynatrace": {
		"APIToken":        "",
		"APIUrl":          "",
		"CheckCert":       true,
		"MinimumPriority": "",
	},
	"Talon": {
		"Address":         "",
		"MinimumPriority": "",
		"CheckCert":       true,
	},
}

func init() {
	for name, dst := range httpOutputDefaults {
		// Apply common http output defaults to http output defaults
		for k, v := range commonHttpOutputDefaults {
			dst[k] = v
		}

		// Merge http outputs defaults with other outputs defaults
		if _, ok := outputDefaults[name]; ok {
			panic(fmt.Sprintf("key %v already set in the output defaults", name))
		}
		outputDefaults[name] = dst
	}
}

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

	// Set outputs defaults
	for prefix, m := range outputDefaults {
		for key, val := range m {
			v.SetDefault(prefix+"."+key, val)
		}
	}

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

	v.SetDefault("Alertmanager.MinimumPriority", "")

	v.SetDefault("Prometheus.ExtraLabels", "")

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
	v.GetStringSlice("Customtags")

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

	if value, present := os.LookupEnv("CUSTOMTAGS"); present {
		c.Customtags = strings.Split(strings.ReplaceAll(value, " ", ""), ",")
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

	if c.Elasticsearch.NumberOfReplicas <= 0 {
		c.Elasticsearch.NumberOfReplicas = 3
	}
	if c.Elasticsearch.NumberOfShards <= 0 {
		c.Elasticsearch.NumberOfShards = 3
	}

	if c.Elasticsearch.Batching.Enabled {
		if c.Elasticsearch.Batching.BatchSize <= 0 {
			c.Elasticsearch.Batching.BatchSize = types.DefaultBatchSize
		}
		if c.Elasticsearch.Batching.FlushInterval <= 0 {
			c.Elasticsearch.Batching.FlushInterval = types.DefaultFlushInterval
		}
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
			if p := strings.TrimSpace(values[1]); p == "" {
				log.Printf("[ERROR] : AlertManager - Priority '%v' is not a valid falco priority level", p)
				continue
			}
			priority := types.Priority(strings.TrimSpace(values[1]))
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
	c.Webex.MinimumPriority = checkPriority(c.Webex.MinimumPriority)
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
	c.SumoLogic.MinimumPriority = checkPriority(c.SumoLogic.MinimumPriority)
	c.Talon.MinimumPriority = checkPriority(c.Talon.MinimumPriority)

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
