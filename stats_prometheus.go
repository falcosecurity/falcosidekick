// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const metricPrefix string = "falcosecurity_falcosidekick_"

func getInitPromStats(config *types.Configuration) *types.PromStatistics {
	promStats = &types.PromStatistics{
		Inputs:  getInputNewCounterVec(),
		Outputs: getOutputNewCounterVec(),
	}
	return promStats
}

func getInputNewCounterVec() *prometheus.CounterVec {
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: metricPrefix + "inputs_total",
		},
		[]string{"source", "status"},
	)
}

func getOutputNewCounterVec() *prometheus.CounterVec {
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: metricPrefix + "outputs_total",
		},
		[]string{"destination", "status"},
	)
}
