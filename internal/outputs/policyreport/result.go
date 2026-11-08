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
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

// Result values and severities of openreports.io/v1alpha1:
// https://github.com/openreports/reports-api/blob/v0.2.1/apis/openreports.io/v1alpha1/report_types.go
const (
	resultFail = "fail"
	resultWarn = "warn"

	severityInfo     = "info"
	severityLow      = "low"
	severityMedium   = "medium"
	severityHigh     = "high"
	severityCritical = "critical"

	resultSource = "Falco"

	fieldPodName        = "k8s.pod.name"
	fieldNamespace      = "k8s.ns.name"
	fieldTargetNS       = "ka.target.namespace"
	fieldTargetResource = "ka.target.resource"
	fieldTargetName     = "ka.target.name"
	fieldResponseName   = "ka.resp.name"
)

// severityRank orders severities for prune_by_priority; unknown values rank lowest.
var severityRank = map[string]int{
	severityInfo:     1,
	severityLow:      2,
	severityMedium:   3,
	severityHigh:     4,
	severityCritical: 5,
}

type resourceKind struct {
	apiVersion string
	kind       string
}

// resourceKinds maps the resources of the k8saudit ruleset to their kinds.
var resourceKinds = map[string]resourceKind{
	"pods":                {"v1", "Pod"},
	"services":            {"v1", "Service"},
	"secrets":             {"v1", "Secret"},
	"configmaps":          {"v1", "ConfigMap"},
	"namespaces":          {"v1", "Namespace"},
	"serviceaccounts":     {"v1", "ServiceAccount"},
	"daemonsets":          {"apps/v1", "DaemonSet"},
	"deployments":         {"apps/v1", "Deployment"},
	"statefulsets":        {"apps/v1", "StatefulSet"},
	"cronjobs":            {"batch/v1", "CronJob"},
	"jobs":                {"batch/v1", "Job"},
	"clusterroles":        {"rbac.authorization.k8s.io/v1", "ClusterRole"},
	"clusterrolebindings": {"rbac.authorization.k8s.io/v1", "ClusterRoleBinding"},
	"roles":               {"rbac.authorization.k8s.io/v1", "Role"},
	"rolebindings":        {"rbac.authorization.k8s.io/v1", "RoleBinding"},
}

type timestamp struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

type objectReference struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
}

type reportResult struct {
	Properties map[string]string `json:"properties,omitempty"`
	Source     string            `json:"source"`
	Policy     string            `json:"policy"`
	Category   string            `json:"category,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	Result     string            `json:"result,omitempty"`
	Message    string            `json:"message,omitempty"`
	Resources  []objectReference `json:"resources,omitempty"`
	Timestamp  timestamp         `json:"timestamp"`
}

// buildResult maps the Falco rule to the policy and the event source to the category.
func buildResult(evt *event.Event) (map[string]any, error) {
	properties := make(map[string]string, len(evt.OutputFields)+4)
	for k, v := range evt.OutputFields {
		if v != nil {
			properties[k] = fmt.Sprint(v)
		}
	}
	for k, v := range map[string]string{
		"priority": evt.Priority.String(),
		"hostname": evt.Hostname,
		"tags":     shared.FormatTags(evt.Tags, ","),
	} {
		if _, taken := properties[k]; !taken && v != "" {
			properties[k] = v
		}
	}
	// addResult matches retries on it, so an output field of the same name never replaces it.
	if evt.UUID != "" {
		properties["uuid"] = evt.UUID
	}
	r := reportResult{
		Source:     resultSource,
		Policy:     evt.Rule,
		Category:   evt.Source,
		Severity:   mapSeverity(evt.Priority),
		Result:     mapResult(evt.Priority),
		Message:    evt.Output,
		Properties: properties,
		Resources:  resources(evt.OutputFields),
		Timestamp: timestamp{
			Seconds: evt.Time.Unix(),
			Nanos:   int32(evt.Time.Nanosecond()), //nolint:gosec // Nanosecond is below 1e9
		},
	}
	return runtime.DefaultUnstructuredConverter.ToUnstructured(&r)
}

// mapResult maps warning and below to warn, the rest to fail: skip means the policy was not
// selected, and every Falco event is an alert.
func mapResult(p event.Priority) string {
	if p.Order() <= event.PriorityWarning.Order() {
		return resultWarn
	}
	return resultFail
}

func mapSeverity(p event.Priority) string {
	switch {
	case p.Order() <= event.PriorityInformational.Order():
		return severityInfo
	case p == event.PriorityNotice:
		return severityLow
	case p == event.PriorityWarning:
		return severityMedium
	case p == event.PriorityError:
		return severityHigh
	default:
		return severityCritical
	}
}

// namespaceOf returns "" when the event has no valid namespace name.
func namespaceOf(fields map[string]any) string {
	for _, key := range []string{fieldNamespace, fieldTargetNS} {
		v, ok := fields[key]
		if !ok || v == nil {
			continue
		}
		ns := fmt.Sprint(v)
		if len(validation.IsDNS1123Label(ns)) == 0 {
			return ns
		}
	}
	return ""
}

func resources(fields map[string]any) []objectReference {
	name, resource := resourceNameKind(fields)
	kind, ok := resourceKinds[resource]
	if name == "" || !ok {
		return nil
	}
	return []objectReference{{
		APIVersion: kind.apiVersion,
		Kind:       kind.kind,
		Name:       name,
		Namespace:  namespaceOf(fields),
	}}
}

func resourceNameKind(fields map[string]any) (name, resource string) {
	str := func(key string) string {
		if v, ok := fields[key]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	if pod := str(fieldPodName); pod != "" {
		return pod, "pods"
	}
	resource = str(fieldTargetResource)
	if resource == "" {
		return "", ""
	}
	if n := str(fieldTargetName); n != "" {
		return n, resource
	}
	return str(fieldResponseName), resource
}
