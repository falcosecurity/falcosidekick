package main

import (
	"expvar"

	"github.com/Issif/falcosidekick/types"
)

func getInitStats() *types.Statistics {
	stats = &types.Statistics{
		Requests:      expvar.NewMap("requests"),
		Slack:         expvar.NewMap("outputs.slack"),
		Datadog:       expvar.NewMap("outputs.datadog"),
		Alertmanager:  expvar.NewMap("outputs.alertmanager"),
		Elasticsearch: expvar.NewMap("outputs.elasticsearch"),
		Influxdb:      expvar.NewMap("outputs.influxdb"),
	}
	stats.Requests.Add("total", 0)
	stats.Requests.Add("rejected", 0)
	stats.Requests.Add("accepted", 0)
	stats.Slack.Add("total", 0)
	stats.Slack.Add("error", 0)
	stats.Slack.Add("sent", 0)
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

	return stats
}
