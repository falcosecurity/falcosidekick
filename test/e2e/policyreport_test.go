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

//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// envKubeconfig is a kubeconfig for a cluster with the openreports.io CRDs
// installed: https://github.com/openreports/reports-api/releases
const envKubeconfig = "FALCOSIDEKICK_E2E_KUBECONFIG"

const policyReportName = "falcosidekick"

var (
	reportsGVR        = schema.GroupVersionResource{Group: "openreports.io", Version: "v1alpha1", Resource: "reports"}
	clusterReportsGVR = schema.GroupVersionResource{Group: "openreports.io", Version: "v1alpha1", Resource: "clusterreports"}
	namespacesGVR     = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	crdsGVR           = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
)

type kubeTarget struct {
	client     dynamic.Interface
	discovery  discovery.DiscoveryInterface
	kubeconfig string
}

func kubeCluster(t *testing.T) kubeTarget {
	t.Helper()
	path := requireEnv(t, envKubeconfig)
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	require.NoError(t, err)
	client, err := dynamic.NewForConfig(cfg)
	require.NoError(t, err)
	disc, err := discovery.NewDiscoveryClientForConfig(cfg)
	require.NoError(t, err)
	return kubeTarget{client: client, discovery: disc, kubeconfig: path}
}

// createNamespace creates a namespace named after marker and deletes it when the test ends.
func (k kubeTarget) createNamespace(t *testing.T, prefix, marker string) string {
	t.Helper()
	ns := prefix + "-" + marker
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns},
	}}
	_, err := k.client.Resource(namespacesGVR).Create(context.Background(), obj, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = k.client.Resource(namespacesGVR).Delete(context.Background(), ns, metav1.DeleteOptions{})
	})
	return ns
}

// results returns the results of the report in namespace, or of the
// ClusterReport when namespace is empty, that carry marker.
func (k kubeTarget) results(t *testing.T, namespace, marker string) (report *unstructured.Unstructured, found []map[string]any) {
	t.Helper()
	var err error
	if namespace == "" {
		report, err = k.client.Resource(clusterReportsGVR).Get(context.Background(), policyReportName, metav1.GetOptions{})
	} else {
		report, err = k.client.Resource(reportsGVR).Namespace(namespace).Get(context.Background(), policyReportName, metav1.GetOptions{})
	}
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	require.NoError(t, err)
	results, _, err := unstructured.NestedSlice(report.Object, "results")
	require.NoError(t, err)
	for _, r := range results {
		m, _ := r.(map[string]any)
		props, _ := m["properties"].(map[string]any)
		if props["e2e.marker"] == marker {
			found = append(found, m)
		}
	}
	return report, found
}

func (k kubeTarget) waitResult(t *testing.T, namespace, marker string) (report *unstructured.Unstructured, result map[string]any) {
	t.Helper()
	var found []map[string]any
	eventuallyf(t, func() bool {
		report, found = k.results(t, namespace, marker)
		return len(found) > 0
	}, "result %s in namespace %q", marker, namespace)
	require.Len(t, found, 1)
	return report, found[0]
}

func policyReportOutput(kubeconfig, fallback string) string {
	return fmt.Sprintf("policyreport:\n  kubeconfig: %q\n  falco_namespace: %q\n", kubeconfig, fallback)
}

func postFields(t *testing.T, sk *sidekick, marker, priority string, fields map[string]any) {
	t.Helper()
	evt := falcoEvent(marker)
	evt["priority"] = priority
	outputFields := evt["output_fields"].(map[string]any)
	for k, v := range fields {
		outputFields[k] = v
	}
	body, err := json.Marshal(evt)
	require.NoError(t, err)
	resp, err := httpDo(http.MethodPost, sk.url+"/", body)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPolicyReportWritesNamespaceReport(t *testing.T) {
	k := kubeCluster(t)
	marker := newMarker(t)
	ns := k.createNamespace(t, "e2e", marker)
	sk := startSidekick(t, policyReportOutput(k.kubeconfig, "default"))
	assert.Equal(t, "idle", sk.status(t, "policyreport").Status, "the health probe passed")

	postFields(t, sk, marker, "Warning", map[string]any{"k8s.ns.name": ns, "k8s.pod.name": "api-0"})
	report, result := k.waitResult(t, ns, marker)
	sk.waitStatus(t, "policyreport", func(st outputStatus) bool { return st.SentTotal == 1 })

	assert.Equal(t, "Report", report.GetKind())
	assert.Equal(t, "falcosidekick", report.GetLabels()["app.kubernetes.io/managed-by"])
	source, _, _ := unstructured.NestedString(report.Object, "source")
	assert.Equal(t, "Falco", source)
	warn, _, _ := unstructured.NestedInt64(report.Object, "summary", "warn")
	assert.Equal(t, int64(1), warn)
	limit, _, _ := unstructured.NestedInt64(report.Object, "configuration", "limits", "maxResults")
	assert.Equal(t, int64(1000), limit)

	assert.Equal(t, "E2E "+marker, result["policy"])
	assert.Equal(t, "syscall", result["category"])
	assert.Equal(t, "warn", result["result"])
	assert.Equal(t, "medium", result["severity"])
	assert.Equal(t, "e2e event "+marker, result["message"])
	ts, _ := result["timestamp"].(map[string]any)
	assert.Positive(t, ts["seconds"])
	assert.Equal(t, []any{map[string]any{"apiVersion": "v1", "kind": "Pod", "name": "api-0", "namespace": ns}}, result["resources"])
	props, _ := result["properties"].(map[string]any)
	assert.Equal(t, "warning", props["priority"])
	assert.Equal(t, "e2e-host", props["hostname"])
}

func TestPolicyReportWritesClusterReport(t *testing.T) {
	k := kubeCluster(t)
	marker := newMarker(t)
	sk := startSidekick(t, policyReportOutput(k.kubeconfig, "default"))

	postFields(t, sk, marker, "Critical", nil)
	report, result := k.waitResult(t, "", marker)
	assert.Equal(t, "ClusterReport", report.GetKind())
	assert.Equal(t, "fail", result["result"])
	assert.Equal(t, "critical", result["severity"])
	assert.NotContains(t, result, "resources")
}

// Concurrent events to one report all land: writes are serialized and
// retried on conflict.
func TestPolicyReportKeepsConcurrentEvents(t *testing.T) {
	k := kubeCluster(t)
	marker := newMarker(t)
	ns := k.createNamespace(t, "e2e", marker)
	sk := startSidekick(t, policyReportOutput(k.kubeconfig, "default")+"  runtime:\n    workers: 4\n")

	const events = 20
	for i := range events {
		postFields(t, sk, fmt.Sprintf("%s-%d", marker, i), "Error", map[string]any{"k8s.ns.name": ns})
	}
	sk.waitStatus(t, "policyreport", func(st outputStatus) bool { return st.SentTotal+st.FailedTotal == events })
	assert.Zero(t, sk.status(t, "policyreport").FailedTotal)
	report, _ := k.results(t, ns, "")
	require.NotNil(t, report)
	results, _, _ := unstructured.NestedSlice(report.Object, "results")
	assert.Len(t, results, events)
	fail, _, _ := unstructured.NestedInt64(report.Object, "summary", "fail")
	assert.Equal(t, int64(events), fail)
}

func TestPolicyReportFallsBackForMissingNamespace(t *testing.T) {
	k := kubeCluster(t)
	marker := newMarker(t)
	fallback := k.createNamespace(t, "fallback", marker)
	sk := startSidekick(t, policyReportOutput(k.kubeconfig, fallback))

	postFields(t, sk, marker, "Error", map[string]any{"k8s.ns.name": "absent-" + marker, "k8s.pod.name": "p"})
	_, result := k.waitResult(t, fallback, marker)
	resources, _ := result["resources"].([]any)
	require.Len(t, resources, 1)
	assert.Equal(t, "absent-"+marker, resources[0].(map[string]any)["namespace"])
}

func TestPolicyReportMissingCRDFailsStartup(t *testing.T) {
	k := kubeCluster(t)
	const crdName = "clusterreports.openreports.io"
	crd, err := k.client.Resource(crdsGVR).Get(context.Background(), crdName, metav1.GetOptions{})
	require.NoError(t, err)
	require.NoError(t, k.client.Resource(crdsGVR).Delete(context.Background(), crdName, metav1.DeleteOptions{}))
	t.Cleanup(func() { restoreCRD(t, k, crd) })
	eventuallyf(t, func() bool { return !servesResource(k, clusterReportsGVR) }, "%s still served", crdName)

	logs := startSidekickFails(t, policyReportOutput(k.kubeconfig, "default"))
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "openreports.io/v1alpha1 does not serve clusterreports")
}

func restoreCRD(t *testing.T, k kubeTarget, crd *unstructured.Unstructured) {
	t.Helper()
	restored := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": crd.GetAPIVersion(), "kind": crd.GetKind(),
		"metadata": map[string]any{"name": crd.GetName(), "labels": toAny(crd.GetLabels()), "annotations": toAny(crd.GetAnnotations())},
		"spec":     crd.Object["spec"],
	}}
	eventuallyf(t, func() bool {
		_, err := k.client.Resource(crdsGVR).Create(context.Background(), restored, metav1.CreateOptions{})
		return err == nil || apierrors.IsAlreadyExists(err)
	}, "recreate %s", crd.GetName())
	eventuallyf(t, func() bool { return servesResource(k, clusterReportsGVR) }, "%s not served", crd.GetName())
}

func toAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func servesResource(k kubeTarget, gvr schema.GroupVersionResource) bool {
	list, err := k.discovery.ServerResourcesForGroupVersion(gvr.GroupVersion().String())
	if err != nil {
		return false
	}
	return slices.ContainsFunc(list.APIResources, func(r metav1.APIResource) bool { return r.Name == gvr.Resource })
}

// kubeconfigWithToken copies the cluster and CA of the test kubeconfig with a
// bearer token as the only credential.
func kubeconfigWithToken(t *testing.T, k kubeTarget, server, token string) string {
	t.Helper()
	cfg, err := clientcmd.LoadFromFile(k.kubeconfig)
	require.NoError(t, err)
	current := cfg.Contexts[cfg.CurrentContext]
	require.NotNil(t, current)
	cluster := cfg.Clusters[current.Cluster]
	if server != "" {
		cluster.Server = server
	}
	user := cfg.AuthInfos[current.AuthInfo]
	user.ClientCertificateData, user.ClientKeyData, user.Token = nil, nil, token
	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, clientcmd.WriteToFile(*cfg, path))
	return path
}

func TestPolicyReportRejectedTokenFailsStartup(t *testing.T) {
	k := kubeCluster(t)
	const token = "e2e-rejected-kube-token"
	logs := startSidekickFails(t, policyReportOutput(kubeconfigWithToken(t, k, "", token), "default"))
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "HTTP 401")
	assert.NotContains(t, logs, token)
}

func TestPolicyReportUnreachableAtStartupDegrades(t *testing.T) {
	k := kubeCluster(t)
	sk := startSidekick(t, policyReportOutput(kubeconfigWithToken(t, k, "https://127.0.0.1:1", "e2e-token"), "default"))
	st := sk.status(t, "policyreport")
	assert.Equal(t, "degraded", st.Status, "an unreachable API server at startup is transient")
	assert.Contains(t, st.LastWarning, "health check failed before start")
}

func TestPolicyReportCredentialsAbsentFromLogsAndAPI(t *testing.T) {
	k := kubeCluster(t)
	const token = "e2e-secret-kube-token"
	sk := startSidekick(t, policyReportOutput(kubeconfigWithToken(t, k, "https://127.0.0.1:1", token), "default"))
	sk.postEvent(t, newMarker(t))
	sk.waitStatus(t, "policyreport", func(st outputStatus) bool { return st.FailedTotal == 1 })
	for _, path := range []string{"/api/v1/config", "/api/v1/pipeline/outputs/policyreport", "/api/v1/pipeline/status/policyreport"} {
		resp, err := httpDo(http.MethodGet, sk.url+path, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		assert.NotContains(t, string(body), token, path)
	}
	assert.NotContains(t, sk.logs.String(), token)
}
