// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package policyreport

import (
	"slices"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	group   = "openreports.io"
	version = "v1alpha1"

	reportKind        = "Report"
	clusterReportKind = "ClusterReport"

	// reportName names both the Report of each namespace and the ClusterReport.
	reportName = "falcosidekick"

	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "falcosidekick"
)

var (
	reportsGVR        = schema.GroupVersionResource{Group: group, Version: version, Resource: "reports"}
	clusterReportsGVR = schema.GroupVersionResource{Group: group, Version: version, Resource: "clusterreports"}
)

// target is a Report in namespace, or the ClusterReport when namespace is empty.
type target struct {
	namespace string
}

func newReport(t target) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{"source": resultSource}}
	obj.SetAPIVersion(group + "/" + version)
	if t.namespace == "" {
		obj.SetKind(clusterReportKind)
	} else {
		obj.SetKind(reportKind)
		obj.SetNamespace(t.namespace)
	}
	obj.SetName(reportName)
	obj.SetLabels(map[string]string{managedByLabel: managedByValue})
	return obj
}

// addResult prunes results beyond maxEvents and declares it as configuration.limits.maxResults.
func addResult(obj *unstructured.Unstructured, result map[string]any, maxEvents int, pruneByPriority bool) {
	_ = unstructured.SetNestedField(obj.Object, int64(maxEvents), "configuration", "limits", "maxResults")
	results, _ := obj.Object["results"].([]any)
	// A retry after a write whose answer was lost finds the result already there.
	if id := property(result, "uuid"); id != "" && slices.ContainsFunc(results, func(r any) bool { return property(r, "uuid") == id }) {
		return
	}
	results = append(results, result)
	for len(results) > maxEvents {
		i := 0
		if pruneByPriority {
			i = lowestSeverity(results)
		}
		results = append(results[:i], results[i+1:]...)
	}
	obj.Object["results"] = results
	obj.Object["summary"] = summarize(results)
}

// lowestSeverity returns the index of the oldest result with the lowest severity.
func lowestSeverity(results []any) int {
	lowest, rank := 0, -1
	for i, r := range results {
		if n := severityRank[field(r, "severity")]; rank < 0 || n < rank {
			lowest, rank = i, n
		}
	}
	return lowest
}

func summarize(results []any) map[string]any {
	counts := map[string]int64{"pass": 0, "fail": 0, "warn": 0, "error": 0, "skip": 0}
	for _, r := range results {
		res := field(r, "result")
		if _, ok := counts[res]; ok {
			counts[res]++
		}
	}
	summary := make(map[string]any, len(counts))
	for k, v := range counts {
		summary[k] = v
	}
	return summary
}

func field(result any, key string) string {
	m, _ := result.(map[string]any)
	s, _ := m[key].(string)
	return s
}

// property reads a result property, typed as built or as decoded from the API server.
func property(result any, key string) string {
	m, _ := result.(map[string]any)
	switch properties := m["properties"].(type) {
	case map[string]string:
		return properties[key]
	case map[string]any:
		s, _ := properties[key].(string)
		return s
	}
	return ""
}
