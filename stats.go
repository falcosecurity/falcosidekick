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
		Rocketchat:        getOutputNewMap("rocketchat"),
		Mattermost:        getOutputNewMap("mattermost"),
		Teams:             getOutputNewMap("teams"),
		Datadog:           getOutputNewMap("datadog"),
		Discord:           getOutputNewMap("discord"),
		Alertmanager:      getOutputNewMap("alertmanager"),
		Elasticsearch:     getOutputNewMap("elasticsearch"),
		Loki:              getOutputNewMap("loki"),
		Nats:              getOutputNewMap("nats"),
		Stan:              getOutputNewMap("stan"),
		Influxdb:          getOutputNewMap("influxdb"),
		AWSLambda:         getOutputNewMap("awslambda"),
		AWSSQS:            getOutputNewMap("awssqs"),
		AWSSNS:            getOutputNewMap("awssns"),
		AWSCloudWatchLogs: getOutputNewMap("awscloudwatchlogs"),
		SMTP:              getOutputNewMap("smtp"),
		Opsgenie:          getOutputNewMap("opsgenie"),
		Statsd:            getOutputNewMap("statsd"),
		Dogstatsd:         getOutputNewMap("dogstatsd"),
		Webhook:           getOutputNewMap("webhook"),
		CloudEvents:       getOutputNewMap("cloudevents"),
		AzureEventHub:     getOutputNewMap("azureeventhub"),
		GCPPubSub:         getOutputNewMap("gcppubsub"),
		GoogleChat:        getOutputNewMap("googlechat"),
		Kafka:             getOutputNewMap("kafka"),
		Pagerduty:         getOutputNewMap("pagerduty"),
		Kubeless:          getOutputNewMap("kubeless"),
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
