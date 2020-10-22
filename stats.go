package main

import (
	"expvar"
	"fmt"
	"runtime"

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
		Requests:      getInputNewMap("requests"),
		FIFO:          getInputNewMap("fifo"),
		GRPC:          getInputNewMap("grpc"),
		Falco:         expvar.NewMap("falco.priority"),
		Slack:         expvar.NewMap("outputs.slack"),
		Rocketchat:    expvar.NewMap("outputs.rocketchat"),
		Mattermost:    expvar.NewMap("outputs.mattermost"),
		Teams:         expvar.NewMap("outputs.teams"),
		Datadog:       expvar.NewMap("outputs.datadog"),
		Discord:       expvar.NewMap("outputs.discord"),
		Alertmanager:  expvar.NewMap("outputs.alertmanager"),
		Elasticsearch: expvar.NewMap("outputs.elasticsearch"),
		Loki:          expvar.NewMap("outputs.loki"),
		Nats:          expvar.NewMap("outputs.nats"),
		Influxdb:      expvar.NewMap("outputs.influxdb"),
		AWSLambda:     expvar.NewMap("outputs.awslambda"),
		AWSSQS:        expvar.NewMap("outputs.awssqs"),
		AWSSNS:        expvar.NewMap("outputs.awssns"),
		SMTP:          expvar.NewMap("outputs.smtp"),
		Opsgenie:      expvar.NewMap("outputs.opsgenie"),
		Statsd:        expvar.NewMap("outputs.statsd"),
		Dogstatsd:     expvar.NewMap("outputs.dogstatsd"),
		Webhook:       expvar.NewMap("outputs.webhook"),
		AzureEventHub: expvar.NewMap("outputs.azureeventhub"),
		GCPPubSub:     expvar.NewMap("outputs.gcppubsub"),
	}
	stats.Falco.Add("emergency", 0)
	stats.Falco.Add("alert", 0)
	stats.Falco.Add("critical", 0)
	stats.Falco.Add("error", 0)
	stats.Falco.Add("warning", 0)
	stats.Falco.Add("notice", 0)
	stats.Falco.Add("informational", 0)
	stats.Falco.Add("debug", 0)
	stats.Falco.Add("unknown", 0)
	stats.Slack.Add("total", 0)
	stats.Slack.Add("error", 0)
	stats.Slack.Add("ok", 0)
	stats.Rocketchat.Add("total", 0)
	stats.Rocketchat.Add("error", 0)
	stats.Rocketchat.Add("ok", 0)
	stats.Mattermost.Add("total", 0)
	stats.Mattermost.Add("error", 0)
	stats.Mattermost.Add("ok", 0)
	stats.Teams.Add("total", 0)
	stats.Teams.Add("error", 0)
	stats.Teams.Add("ok", 0)
	stats.Datadog.Add("total", 0)
	stats.Datadog.Add("error", 0)
	stats.Datadog.Add("ok", 0)
	stats.Discord.Add("total", 0)
	stats.Discord.Add("error", 0)
	stats.Discord.Add("ok", 0)
	stats.Alertmanager.Add("total", 0)
	stats.Alertmanager.Add("error", 0)
	stats.Alertmanager.Add("ok", 0)
	stats.Elasticsearch.Add("total", 0)
	stats.Elasticsearch.Add("error", 0)
	stats.Elasticsearch.Add("ok", 0)
	stats.Influxdb.Add("total", 0)
	stats.Influxdb.Add("error", 0)
	stats.Influxdb.Add("ok", 0)
	stats.Loki.Add("total", 0)
	stats.Loki.Add("error", 0)
	stats.Loki.Add("ok", 0)
	stats.Nats.Add("total", 0)
	stats.Nats.Add("error", 0)
	stats.Nats.Add("ok", 0)
	stats.AWSLambda.Add("total", 0)
	stats.AWSLambda.Add("error", 0)
	stats.AWSLambda.Add("ok", 0)
	stats.AWSSQS.Add("total", 0)
	stats.AWSSQS.Add("error", 0)
	stats.AWSSQS.Add("ok", 0)
	stats.AWSSNS.Add("total", 0)
	stats.AWSSNS.Add("error", 0)
	stats.AWSSNS.Add("ok", 0)
	stats.SMTP.Add("total", 0)
	stats.SMTP.Add("error", 0)
	stats.SMTP.Add("ok", 0)
	stats.Opsgenie.Add("total", 0)
	stats.Opsgenie.Add("error", 0)
	stats.Opsgenie.Add("ok", 0)
	stats.Statsd.Add("total", 0)
	stats.Statsd.Add("error", 0)
	stats.Statsd.Add("ok", 0)
	stats.Dogstatsd.Add("total", 0)
	stats.Dogstatsd.Add("error", 0)
	stats.Dogstatsd.Add("ok", 0)
	stats.Webhook.Add("total", 0)
	stats.Webhook.Add("error", 0)
	stats.Webhook.Add("ok", 0)
	stats.AzureEventHub.Add("total", 0)
	stats.AzureEventHub.Add("error", 0)
	stats.AzureEventHub.Add("ok", 0)
        stats.GCPPubSub.Add("total", 0)
        stats.GCPPubSub.Add("error", 0)
        stats.GCPPubSub.Add("ok", 0)
	return stats
}

func getInputNewMap(s string) *expvar.Map {
	e := expvar.NewMap("inputs." + s)
	e.Add("total", 0)
	e.Add("rejected", 0)
	e.Add("accepted", 0)
	return e
}

func getOutputNewMap(s string) *expvar.Map {
	e := expvar.NewMap("outputs." + s)
	e.Add("total", 0)
	e.Add("error", 0)
	e.Add("ok", 0)
	return e
}
