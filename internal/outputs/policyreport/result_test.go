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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestPriorityMapping(t *testing.T) {
	tests := []struct {
		priority event.Priority
		result   string
		severity string
	}{
		{event.PriorityDebug, resultSkip, severityInfo},
		{event.PriorityInformational, resultSkip, severityInfo},
		{event.PriorityNotice, resultSkip, severityLow},
		{event.PriorityWarning, resultWarn, severityMedium},
		{event.PriorityError, resultFail, severityHigh},
		{event.PriorityCritical, resultFail, severityCritical},
		{event.PriorityAlert, resultFail, severityCritical},
		{event.PriorityEmergency, resultFail, severityCritical},
	}
	for _, tt := range tests {
		t.Run(string(tt.priority), func(t *testing.T) {
			assert.Equal(t, tt.result, mapResult(tt.priority))
			assert.Equal(t, tt.severity, mapSeverity(tt.priority))
		})
	}
}

func TestBuildResult(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Time = time.Date(2026, 4, 1, 10, 30, 0, 123456789, time.UTC)
	evt.OutputFields["k8s.ns.name"] = "prod"
	evt.OutputFields["k8s.pod.name"] = "api-0"
	evt.OutputFields["proc.pid"] = 42
	evt.OutputFields["container.name"] = nil

	got, err := buildResult(evt)
	require.NoError(t, err)

	assert.Equal(t, "Falco", got["source"])
	assert.Equal(t, evt.Rule, got["policy"])
	assert.NotContains(t, got, "rule")
	assert.Equal(t, "syscall", got["category"])
	assert.Equal(t, severityHigh, got["severity"])
	assert.Equal(t, resultFail, got["result"])
	assert.Equal(t, evt.Output, got["message"])
	assert.Equal(t, map[string]any{"seconds": evt.Time.Unix(), "nanos": int64(123456789)}, got["timestamp"])

	props, ok := got["properties"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "42", props["proc.pid"])
	assert.Equal(t, "/bin/hack", props["fd.name"])
	assert.NotContains(t, props, "container.name", "null fields are left out")
	assert.Equal(t, "error", props["priority"])
	assert.Equal(t, "node-1", props["hostname"])
	assert.Equal(t, "filesystem,mitre_persistence", props["tags"])
	assert.Equal(t, "test-uuid-001", props["uuid"])

	assert.Equal(t, []any{map[string]any{
		"apiVersion": "v1", "kind": "Pod", "name": "api-0", "namespace": "prod",
	}}, got["resources"])
}

func TestBuildResultMinimalEvent(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Time = time.Unix(10, 0)
	evt.Hostname, evt.UUID, evt.Tags = "", "", nil
	evt.OutputFields["priority"] = "from the rule output"
	got, err := buildResult(evt)
	require.NoError(t, err)
	assert.NotContains(t, got, "resources")
	props := got["properties"].(map[string]any)
	assert.Equal(t, "from the rule output", props["priority"], "output fields take precedence")
	assert.NotContains(t, props, "hostname")
	assert.NotContains(t, props, "tags")
	assert.NotContains(t, props, "uuid")
	assert.Equal(t, map[string]any{"seconds": int64(10), "nanos": int64(0)}, got["timestamp"], "nanos is required by the CRD")
}

func TestResources(t *testing.T) {
	tests := []struct {
		fields map[string]any
		name   string
		want   []objectReference
	}{
		{name: "pod", fields: map[string]any{"k8s.pod.name": "p", "k8s.ns.name": "ns"},
			want: []objectReference{{APIVersion: "v1", Kind: "Pod", Name: "p", Namespace: "ns"}}},
		{name: "audit target name", fields: map[string]any{"ka.target.resource": "secrets", "ka.target.name": "s", "ka.target.namespace": "ns"},
			want: []objectReference{{APIVersion: "v1", Kind: "Secret", Name: "s", Namespace: "ns"}}},
		{name: "audit response name", fields: map[string]any{"ka.target.resource": "clusterroles", "ka.resp.name": "admin"},
			want: []objectReference{{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "admin"}}},
		{name: "unknown resource", fields: map[string]any{"ka.target.resource": "widgets", "ka.target.name": "w"}},
		{name: "resource without name", fields: map[string]any{"ka.target.resource": "pods"}},
		{name: "no resource", fields: map[string]any{"proc.name": "sh"}},
		{name: "null pod", fields: map[string]any{"k8s.pod.name": nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resources(tt.fields))
		})
	}
}

func TestNamespaceOf(t *testing.T) {
	tests := []struct {
		fields map[string]any
		name   string
		want   string
	}{
		{name: "k8s.ns.name", fields: map[string]any{"k8s.ns.name": "prod", "ka.target.namespace": "other"}, want: "prod"},
		{name: "ka.target.namespace", fields: map[string]any{"ka.target.namespace": "kube-system"}, want: "kube-system"},
		{name: "none", fields: map[string]any{"proc.name": "sh"}},
		{name: "null", fields: map[string]any{"k8s.ns.name": nil}},
		{name: "not available", fields: map[string]any{"k8s.ns.name": "<NA>"}},
		{name: "invalid then valid", fields: map[string]any{"k8s.ns.name": "", "ka.target.namespace": "audit"}, want: "audit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, namespaceOf(tt.fields))
		})
	}
}

func resultWith(severity, result string) map[string]any {
	return map[string]any{"policy": "syscall", "severity": severity, "result": result}
}

func TestAddResultRotation(t *testing.T) {
	tests := []struct {
		results []map[string]any
		name    string
		want    []string // severities left, oldest first
		prune   bool
	}{
		{
			name:    "oldest first",
			results: []map[string]any{resultWith("high", "fail"), resultWith("info", "skip"), resultWith("critical", "fail"), resultWith("low", "skip")},
			want:    []string{"info", "critical", "low"},
		},
		{
			name:    "lowest severity first",
			prune:   true,
			results: []map[string]any{resultWith("high", "fail"), resultWith("low", "skip"), resultWith("medium", "warn"), resultWith("low", "skip")},
			want:    []string{"high", "medium", "low"},
		},
		{
			name:    "oldest of equal severity",
			prune:   true,
			results: []map[string]any{resultWith("critical", "fail"), resultWith("critical", "fail"), resultWith("critical", "warn"), resultWith("critical", "skip")},
			want:    []string{"critical", "critical", "critical"},
		},
		{
			name:    "unknown severity first",
			prune:   true,
			results: []map[string]any{resultWith("info", "skip"), resultWith("", "pass"), resultWith("high", "fail"), resultWith("high", "fail")},
			want:    []string{"info", "high", "high"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := newReport(target{})
			for _, r := range tt.results {
				addResult(obj, r, 3, tt.prune)
			}
			results, _ := obj.Object["results"].([]any)
			got := make([]string, len(results))
			for i, r := range results {
				got[i] = field(r, "severity")
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAddResultSummary(t *testing.T) {
	obj := newReport(target{namespace: "ns"})
	obj.Object["results"] = []any{resultWith("info", "pass"), resultWith("info", "error"), "not a result"}
	addResult(obj, resultWith("high", "fail"), 10, false)
	addResult(obj, resultWith("medium", "warn"), 10, false)
	addResult(obj, resultWith("low", "skip"), 10, false)
	assert.Equal(t, map[string]any{
		"pass": int64(1), "fail": int64(1), "warn": int64(1), "error": int64(1), "skip": int64(1),
	}, obj.Object["summary"])
	limit, _, _ := unstructured.NestedInt64(obj.Object, "configuration", "limits", "maxResults")
	assert.Equal(t, int64(10), limit)
}

func TestNewReport(t *testing.T) {
	cluster := newReport(target{})
	assert.Equal(t, "openreports.io/v1alpha1", cluster.GetAPIVersion())
	assert.Equal(t, "ClusterReport", cluster.GetKind())
	assert.Equal(t, "falcosidekick", cluster.GetName())
	assert.Empty(t, cluster.GetNamespace())
	assert.Equal(t, map[string]string{"app.kubernetes.io/managed-by": "falcosidekick"}, cluster.GetLabels())

	ns := newReport(target{namespace: "prod"})
	assert.Equal(t, "Report", ns.GetKind())
	assert.Equal(t, "falcosidekick", ns.GetName())
	assert.Equal(t, "prod", ns.GetNamespace())
	source, _, _ := unstructured.NestedString(ns.Object, "source")
	assert.Equal(t, "Falco", source)
}
