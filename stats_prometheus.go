package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/falcosecurity/falcosidekick/types"
)

func getInitPromStats() *types.PromStatistics {
	promStats = &types.PromStatistics{
		Falco:   getFalcoNewCounterVec(),
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

func getFalcoNewCounterVec() *prometheus.CounterVec {
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falco_events",
		},
		[]string{
			"rule",
			"priority",
			"k8s_ns_name",
			"k8s_pod_name",
		},
	)
}
