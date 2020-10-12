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
		Slack:         getOutputNewMap("slack"),
		Rocketchat:    getOutputNewMap("rocketchat"),
		Mattermost:    getOutputNewMap("mattermost"),
		Teams:         getOutputNewMap("teams"),
		Datadog:       getOutputNewMap("datadog"),
		Discord:       getOutputNewMap("discord"),
		Alertmanager:  getOutputNewMap("alertmanager"),
		Elasticsearch: getOutputNewMap("elasticsearch"),
		Loki:          getOutputNewMap("loki"),
		Nats:          getOutputNewMap("nats"),
		Influxdb:      getOutputNewMap("influxdb"),
		AWSLambda:     getOutputNewMap("awslambda"),
		AWSSQS:        getOutputNewMap("awssqs"),
		AWSSNS:        getOutputNewMap("awssns"),
		SMTP:          getOutputNewMap("smtp"),
		Opsgenie:      getOutputNewMap("opsgenie"),
		Statsd:        getOutputNewMap("statsd"),
		Dogstatsd:     getOutputNewMap("dogstatsd"),
		Webhook:       getOutputNewMap("webhook"),
		AzureEventHub: getOutputNewMap("azureeventhub"),
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
