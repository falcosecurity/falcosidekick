// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"expvar"
	"fmt"
	"runtime"

	"github.com/falcosecurity/falcosidekick/outputs"
	"github.com/falcosecurity/falcosidekick/types"
)

func getInitStats() *types.Statistics {
	expvar.Publish("goroutines", expvar.Func(func() interface{} {
		return fmt.Sprintf("%d", runtime.NumGoroutine())
	}))
	expvar.Publish("cpu", expvar.Func(func() interface{} {
		return fmt.Sprintf("%d", runtime.NumCPU())
	}))

	stats = &types.Statistics{
		Requests:          getInputNewMap("requests"),
		FIFO:              getInputNewMap("fifo"),
		GRPC:              getInputNewMap("grpc"),
		Falco:             expvar.NewMap("falco.priority"),
		Slack:             getOutputNewMap("slack"),
		Cliq:              getOutputNewMap("cliq"),
		Rocketchat:        getOutputNewMap("rocketchat"),
		Mattermost:        getOutputNewMap("mattermost"),
		Teams:             getOutputNewMap("teams"),
		Datadog:           getOutputNewMap("datadog"),
		Discord:           getOutputNewMap("discord"),
		Alertmanager:      getOutputNewMap("alertmanager"),
		Elasticsearch:     getOutputNewMap("elasticsearch"),
		Quickwit:          getOutputNewMap("quickwit"),
		Loki:              getOutputNewMap("loki"),
		SumoLogic:         getOutputNewMap("sumologic"),
		Nats:              getOutputNewMap("nats"),
		Stan:              getOutputNewMap("stan"),
		Influxdb:          getOutputNewMap("influxdb"),
		AWSLambda:         getOutputNewMap("awslambda"),
		AWSSQS:            getOutputNewMap("awssqs"),
		AWSSNS:            getOutputNewMap("awssns"),
		AWSCloudWatchLogs: getOutputNewMap("awscloudwatchlogs"),
		AWSS3:             getOutputNewMap("awss3"),
		AWSSecurityLake:   getOutputNewMap("awssecuritylake"),
		AWSKinesis:        getOutputNewMap("awskinesis"),
		SMTP:              getOutputNewMap("smtp"),
		Opsgenie:          getOutputNewMap("opsgenie"),
		Statsd:            getOutputNewMap("statsd"),
		Dogstatsd:         getOutputNewMap("dogstatsd"),
		Webhook:           getOutputNewMap("webhook"),
		CloudEvents:       getOutputNewMap("cloudevents"),
		AzureEventHub:     getOutputNewMap("azureeventhub"),
		GCPPubSub:         getOutputNewMap("gcppubsub"),
		GCPStorage:        getOutputNewMap("gcpstorage"),
		GCPCloudFunctions: getOutputNewMap("gcpcloudfunctions"),
		GCPCloudRun:       getOutputNewMap("gcpcloudrun"),
		GoogleChat:        getOutputNewMap("googlechat"),
		Kafka:             getOutputNewMap("kafka"),
		KafkaRest:         getOutputNewMap("kafkarest"),
		Pagerduty:         getOutputNewMap("pagerduty"),
		Kubeless:          getOutputNewMap("kubeless"),
		Openfaas:          getOutputNewMap("openfaas"),
		Tekton:            getOutputNewMap("tekton"),
		WebUI:             getOutputNewMap("webui"),
		Rabbitmq:          getOutputNewMap("rabbitmq"),
		Wavefront:         getOutputNewMap("wavefront"),
		Fission:           getOutputNewMap("fission"),
		Grafana:           getOutputNewMap("grafana"),
		GrafanaOnCall:     getOutputNewMap("grafanaoncall"),
		YandexS3:          getOutputNewMap("yandexs3"),
		YandexDataStreams: getOutputNewMap("yandexdatastreams"),
		Syslog:            getOutputNewMap("syslog"),
		MQTT:              getOutputNewMap("mqtt"),
		Spyderbat:         getOutputNewMap("spyderbat"),
		PolicyReport:      getOutputNewMap("policyreport"),
		NodeRed:           getOutputNewMap("nodered"),
		Zincsearch:        getOutputNewMap("zincsearch"),
		Gotify:            getOutputNewMap("gotify"),
		TimescaleDB:       getOutputNewMap("timescaledb"),
		Redis:             getOutputNewMap("redis"),
		Telegram:          getOutputNewMap("telegram"),
		N8N:               getOutputNewMap("n8n"),
		OpenObserve:       getOutputNewMap("openobserve"),
		Dynatrace:         getOutputNewMap("dynatrace"),
		OTLPTraces:        getOutputNewMap("otlptraces"),
	}
	stats.Falco.Add(outputs.Emergency, 0)
	stats.Falco.Add(outputs.Alert, 0)
	stats.Falco.Add(outputs.Critical, 0)
	stats.Falco.Add(outputs.Error, 0)
	stats.Falco.Add(outputs.Warning, 0)
	stats.Falco.Add(outputs.Notice, 0)
	stats.Falco.Add(outputs.Informational, 0)
	stats.Falco.Add(outputs.Debug, 0)
	stats.Falco.Add(outputs.None, 0)

	return stats
}

func getInputNewMap(s string) *expvar.Map {
	e := expvar.NewMap("inputs." + s)
	e.Add(outputs.Total, 0)
	e.Add(outputs.Rejected, 0)
	e.Add(outputs.Accepted, 0)
	return e
}

func getOutputNewMap(s string) *expvar.Map {
	e := expvar.NewMap("outputs." + s)
	e.Add(outputs.Total, 0)
	e.Add(outputs.Error, 0)
	e.Add(outputs.OK, 0)
	return e
}
