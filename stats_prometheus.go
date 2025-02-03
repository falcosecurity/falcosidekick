// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

const metricPrefix string = "falcosecurity_falcosidekick_"

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

func getFalcoNewCounterVec(config *types.Configuration) *prometheus.CounterVec {
	regPromLabels, _ := regexp.Compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")
	labelnames := []string{
		"hostname",
		"rule",
		"priority",
		"priority_raw",
		"source",
		"k8s_ns_name",
		"k8s_pod_name",
	}
	for i := range config.Customfields {
		if !regPromLabels.MatchString(strings.ReplaceAll(i, ".", "_")) {
			utils.Log(utils.ErrorLvl, "Prometheus", fmt.Sprintf("Custom field '%v' is not a valid prometheus label", i))
			continue
		}
		labelnames = append(labelnames, strings.ReplaceAll(i, ".", "_"))
	}
	for i := range config.Templatedfields {
		if !regPromLabels.MatchString(strings.ReplaceAll(i, ".", "_")) {
			utils.Log(utils.ErrorLvl, "Prometheus", fmt.Sprintf("Templated field '%v' is not a valid prometheus label", i))
			continue
		}
		labelnames = append(labelnames, strings.ReplaceAll(i, ".", "_"))
	}
	for _, i := range config.Prometheus.ExtraLabelsList {
		if !regPromLabels.MatchString(strings.ReplaceAll(i, ".", "_")) {
			utils.Log(utils.ErrorLvl, "Prometheus", fmt.Sprintf("Extra field '%v' is not a valid prometheus label", i))
			continue
		}
		labelnames = append(labelnames, strings.ReplaceAll(i, ".", "_"))
	}
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: metricPrefix + "falco_events_total",
		},
		labelnames,
	)
}
