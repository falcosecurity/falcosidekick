package main

import (
	"log"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/falcosecurity/falcosidekick/types"
)

func getInitPromStats(config *types.Configuration) *types.PromStatistics {
	promStats = &types.PromStatistics{
		Falco:   getFalcoNewCounterVec(config),
		Inputs:  getInputNewCounterVec(),
		Outputs: getOutputNewCounterVec(),
	}
	return promStats
}

func getInputNewCounterVec() *prometheus.CounterVec {
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falcosidekick_inputs",
		},
		[]string{"source", "status"},
	)
}

func getOutputNewCounterVec() *prometheus.CounterVec {
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falcosidekick_outputs",
		},
		[]string{"destination", "status"},
	)
}

func getFalcoNewCounterVec(config *types.Configuration) *prometheus.CounterVec {
	labelnames := []string{
		"rule",
		"priority",
		"k8s_ns_name",
		"k8s_pod_name",
	}
	labelnames = append(labelnames, config.Prometheus.ExtraLabelsList...)
	for key := range config.Customfields {
		matched, err := regexp.MatchString("^[a-zA-Z_:][a-zA-Z0-9_:]*$", key)
		if err != nil {
			log.Printf("Error matching prometheus label from custom fields. Err: %s", err)
			continue
		}
		if matched {
			labelnames = append(labelnames, key)
		}
	}
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falco_events",
		},
		labelnames,
	)
}
