// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"log"
	"regexp"
	"strings"

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
	regPromLabels, _ := regexp.Compile("^[a-zA-Z_:][a-zA-Z0-9_:]*$")
	labelnames := []string{
		"hostname",
		"rule",
		"priority",
		"source",
		"k8s_ns_name",
		"k8s_pod_name",
	}
	for i := range config.Customfields {
		if !regPromLabels.MatchString(i) {
			log.Printf("[ERROR] : Custom field '%v' is not a valid prometheus label", i)
			continue
		}
		labelnames = append(labelnames, i)
	}
	for _, i := range config.Prometheus.ExtraLabelsList {
		if !regPromLabels.MatchString(strings.ReplaceAll(i, ".", "_")) {
			log.Printf("[ERROR] : Extra field '%v' is not a valid prometheus label", i)
			continue
		}
		labelnames = append(labelnames, strings.ReplaceAll(i, ".", "_"))
	}
	return promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "falco_events",
		},
		labelnames,
	)
}
