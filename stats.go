package main

import (
	"expvar"

	"github.com/falcosecurity/falcosidekick/types"
)

func getInitStats() *types.Statistics {
	stats = &types.Statistics{
		Requests:      expvar.NewMap("requests"),
		Slack:         expvar.NewMap("outputs.slack"),
		Teams:         expvar.NewMap("outputs.teams"),
		Datadog:       expvar.NewMap("outputs.datadog"),
		Alertmanager:  expvar.NewMap("outputs.alertmanager"),
		Elasticsearch: expvar.NewMap("outputs.elasticsearch"),
		Loki:          expvar.NewMap("outputs.loki"),
		Nats:          expvar.NewMap("outputs.nats"),
		Influxdb:      expvar.NewMap("outputs.influxdb"),
		AWSLambda:     expvar.NewMap("outputs.awslambda"),
		AWSSQS:        expvar.NewMap("outputs.awssqs"),
		SMTP:          expvar.NewMap("outputs.smtp"),
	}
	stats.Requests.Add("total", 0)
	stats.Requests.Add("rejected", 0)
	stats.Requests.Add("accepted", 0)
	stats.Slack.Add("total", 0)
	stats.Slack.Add("error", 0)
	stats.Slack.Add("sent", 0)
	stats.Teams.Add("total", 0)
	stats.Teams.Add("error", 0)
	stats.Teams.Add("sent", 0)
	stats.Datadog.Add("total", 0)
	stats.Datadog.Add("error", 0)
	stats.Datadog.Add("sent", 0)
	stats.Alertmanager.Add("total", 0)
	stats.Alertmanager.Add("error", 0)
	stats.Alertmanager.Add("sent", 0)
	stats.Elasticsearch.Add("total", 0)
	stats.Elasticsearch.Add("error", 0)
	stats.Elasticsearch.Add("sent", 0)
	stats.Influxdb.Add("total", 0)
	stats.Influxdb.Add("error", 0)
	stats.Influxdb.Add("sent", 0)
	stats.Loki.Add("total", 0)
	stats.Loki.Add("error", 0)
	stats.Loki.Add("sent", 0)
	stats.Nats.Add("total", 0)
	stats.Nats.Add("error", 0)
	stats.Nats.Add("sent", 0)
	stats.AWSLambda.Add("total", 0)
	stats.AWSLambda.Add("error", 0)
	stats.AWSLambda.Add("sent", 0)
	stats.AWSSQS.Add("total", 0)
	stats.AWSSQS.Add("error", 0)
	stats.AWSSQS.Add("sent", 0)
	stats.SMTP.Add("total", 0)
	stats.SMTP.Add("error", 0)
	stats.SMTP.Add("sent", 0)

	return stats
}
