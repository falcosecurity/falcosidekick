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
	"encoding/json"
	"reflect"
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

	// maxReportBytes bounds the encoded report; etcd refuses a request above its 1.5 MiB default.
	maxReportBytes = 512 << 10

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

type merged struct {
	// budgetPruned counts the results removed to keep the encoded report within maxReportBytes.
	budgetPruned int
	kept         int
	changed      bool
}

// merge appends the results whose uuid the report does not hold, prunes by count then by encoded size,
// and recomputes the summary; a result that alone exceeds maxReportBytes is refused.
func merge(obj *unstructured.Unstructured, add []map[string]any, maxResults int, pruneByPriority bool) (merged, error) {
	oldLimit, _, _ := unstructured.NestedFieldNoCopy(obj.Object, "configuration", "limits", "maxResults")
	oldSummary := obj.Object["summary"]
	results, _ := obj.Object["results"].([]any)
	before := len(results)

	// A retry after a write whose answer was lost finds its results already there.
	seen := make(map[string]struct{}, len(results)+len(add))
	for _, r := range results {
		if id := property(r, "uuid"); id != "" {
			seen[id] = struct{}{}
		}
	}
	for _, r := range add {
		if id := property(r, "uuid"); id != "" {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
		}
		results = append(results, r)
	}
	added := len(results) - before

	order := pruneOrder(results, pruneByPriority)
	dropped := make([]bool, len(results))
	removed := 0
	for ; removed < len(results)-maxResults; removed++ {
		dropped[order[removed]] = true
	}
	_ = unstructured.SetNestedField(obj.Object, int64(maxResults), "configuration", "limits", "maxResults")
	setResults(obj, results, dropped)

	out := merged{}
	var sizes []int
	for {
		encoded, err := json.Marshal(obj.Object)
		if err != nil {
			return out, err
		}
		excess := len(encoded) - maxReportBytes
		if excess <= 0 {
			break
		}
		if removed >= len(results)-1 {
			return out, errResultTooLarge
		}
		if sizes == nil {
			sizes = resultSizes(results)
		}
		// Each removed result also takes its separating comma; the loop re-measures the summary.
		for freed := 0; freed < excess && removed < len(results)-1; removed++ {
			i := order[removed]
			dropped[i] = true
			freed += sizes[i] + 1
			out.budgetPruned++
		}
		setResults(obj, results, dropped)
	}

	out.kept = len(results) - removed
	out.changed = added > 0 || removed > 0 || !reflect.DeepEqual(oldLimit, int64(maxResults)) ||
		!reflect.DeepEqual(oldSummary, obj.Object["summary"])
	return out, nil
}

func setResults(obj *unstructured.Unstructured, results []any, dropped []bool) {
	kept := make([]any, 0, len(results))
	for i, r := range results {
		if !dropped[i] {
			kept = append(kept, r)
		}
	}
	obj.Object["results"] = kept
	obj.Object["summary"] = summarize(kept)
}

// resultSizes returns the encoded size of each result; an unencodable one counts as zero.
func resultSizes(results []any) []int {
	sizes := make([]int, len(results))
	for i, r := range results {
		if b, err := json.Marshal(r); err == nil {
			sizes[i] = len(b)
		}
	}
	return sizes
}

// pruneOrder returns the result indexes oldest first, or with pruneByPriority lowest severity first.
func pruneOrder(results []any, pruneByPriority bool) []int {
	order := make([]int, len(results))
	for i := range order {
		order[i] = i
	}
	if pruneByPriority {
		slices.SortStableFunc(order, func(a, b int) int {
			return severityRank[field(results[a], "severity")] - severityRank[field(results[b], "severity")]
		})
	}
	return order
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
