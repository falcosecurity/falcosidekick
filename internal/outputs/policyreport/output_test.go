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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func newFakeClient() *fake.FakeDynamicClient {
	return fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		reportsGVR:        "ReportList",
		clusterReportsGVR: "ClusterReportList",
	})
}

func newFakeDriver(t *testing.T, mutate func(*config)) (*driver, *fake.FakeDynamicClient) {
	t.Helper()
	cfg := config{MaxResults: defaultMaxResults, FallbackNamespace: "falco"}
	if mutate != nil {
		mutate(&cfg)
	}
	client := newFakeClient()
	return newDriver(&cfg, client, nil, nil), client
}

var eventSeq atomic.Int64

// eventIn returns a distinct event: results are deduplicated by event UUID.
func eventIn(namespace, rule string, priority event.Priority) *event.Event {
	evt := testutil.CreateValidEvent()
	evt.UUID = fmt.Sprintf("00000000-0000-4000-8000-%012d", eventSeq.Add(1))
	evt.Rule = rule
	evt.Priority = priority
	if namespace != "" {
		evt.OutputFields["k8s.ns.name"] = namespace
	}
	return evt
}

func getReport(t *testing.T, client *fake.FakeDynamicClient, namespace string) *unstructured.Unstructured {
	t.Helper()
	var (
		obj *unstructured.Unstructured
		err error
	)
	if namespace == "" {
		obj, err = client.Resource(clusterReportsGVR).Get(context.Background(), reportName, metav1.GetOptions{})
	} else {
		obj, err = client.Resource(reportsGVR).Namespace(namespace).Get(context.Background(), reportName, metav1.GetOptions{})
	}
	require.NoError(t, err)
	return obj
}

func rules(t *testing.T, obj *unstructured.Unstructured) []string {
	t.Helper()
	results, _, err := unstructured.NestedSlice(obj.Object, "results")
	require.NoError(t, err)
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = field(r, "policy")
	}
	return out
}

func TestSendRoutesByNamespace(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	ctx := context.Background()
	require.NoError(t, d.Send(ctx, eventIn("prod", "r1", event.PriorityError)))
	require.NoError(t, d.Send(ctx, eventIn("prod", "r2", event.PriorityWarning)))
	require.NoError(t, d.Send(ctx, eventIn("", "r3", event.PriorityCritical)))
	require.NoError(t, d.Send(ctx, eventIn("<NA>", "r4", event.PriorityNotice)))

	report := getReport(t, client, "prod")
	assert.Equal(t, "Report", report.GetKind())
	assert.Equal(t, []string{"r1", "r2"}, rules(t, report))
	summary, _, _ := unstructured.NestedMap(report.Object, "summary")
	assert.Equal(t, int64(1), summary["fail"])
	assert.Equal(t, int64(1), summary["warn"])

	cluster := getReport(t, client, "")
	assert.Equal(t, "ClusterReport", cluster.GetKind())
	assert.Equal(t, []string{"r3", "r4"}, rules(t, cluster))
}

// The API server can apply an update whose answer is lost; the retry must not add the result twice.
func TestSendRetryAfterLostAnswerAddsOneResult(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	ctx := context.Background()
	evt := eventIn("prod", "r1", event.PriorityError)
	require.NoError(t, d.Send(ctx, evt))

	lost := true
	client.PrependReactor("update", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if !lost {
			return false, nil, nil
		}
		lost = false
		obj := action.(k8stesting.UpdateAction).GetObject()
		if err := client.Tracker().Update(action.GetResource(), obj, action.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, nil, errors.New("connection reset after the write")
	})
	second := eventIn("prod", "r2", event.PriorityError)
	require.Error(t, d.Send(ctx, second))
	require.NoError(t, d.Send(ctx, second), "pipeline retry")
	require.NoError(t, d.Send(ctx, evt), "an older event retried")

	assert.Equal(t, []string{"r1", "r2"}, rules(t, getReport(t, client, "prod")))
}

// A custom field named uuid used to replace the event UUID, so every later event looked like a retry.
func TestOutputFieldNamedUUIDDoesNotMergeEvents(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	ctx := context.Background()
	for _, rule := range []string{"r1", "r2"} {
		evt := eventIn("prod", rule, event.PriorityError)
		evt.OutputFields["uuid"] = "cluster-a"
		require.NoError(t, d.Send(ctx, evt))
	}
	assert.Equal(t, []string{"r1", "r2"}, rules(t, getReport(t, client, "prod")))
}

func TestSendRotatesAtMaxEvents(t *testing.T) {
	for _, prune := range []bool{false, true} {
		t.Run(fmt.Sprintf("prune_by_priority=%t", prune), func(t *testing.T) {
			d, client := newFakeDriver(t, func(c *config) { c.MaxResults = 2; c.PruneByPriority = prune })
			ctx := context.Background()
			require.NoError(t, d.Send(ctx, eventIn("", "critical", event.PriorityCritical)))
			require.NoError(t, d.Send(ctx, eventIn("", "notice", event.PriorityNotice)))
			require.NoError(t, d.Send(ctx, eventIn("", "error", event.PriorityError)))
			want := []string{"notice", "error"}
			if prune {
				want = []string{"critical", "error"}
			}
			assert.Equal(t, want, rules(t, getReport(t, client, "")))
		})
	}
}

func TestSendRetriesOnConflict(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	ctx := context.Background()
	require.NoError(t, d.Send(ctx, eventIn("prod", "first", event.PriorityError)))

	var updates atomic.Int32
	client.PrependReactor("update", "reports", func(k8stesting.Action) (bool, runtime.Object, error) {
		if updates.Add(1) == 1 {
			return true, nil, apierrors.NewConflict(reportsGVR.GroupResource(), reportName, errors.New("modified"))
		}
		return false, nil, nil
	})
	require.NoError(t, d.Send(ctx, eventIn("prod", "second", event.PriorityError)))
	assert.Equal(t, int32(2), updates.Load())
	assert.Equal(t, []string{"first", "second"}, rules(t, getReport(t, client, "prod")))
}

func TestSendRetriesWhenCreatedConcurrently(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	var creates atomic.Int32
	client.PrependReactor("create", "clusterreports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if creates.Add(1) == 1 {
			// Another writer creates the report between our read and create.
			other := newReport(target{})
			addResult(other, map[string]any{"policy": "other", "rule": "other"}, 10, false)
			require.NoError(t, client.Tracker().Create(clusterReportsGVR, other, ""))
			return true, nil, apierrors.NewAlreadyExists(clusterReportsGVR.GroupResource(), reportName)
		}
		return false, nil, nil
	})
	require.NoError(t, d.Send(context.Background(), eventIn("", "mine", event.PriorityError)))
	assert.Equal(t, []string{"other", "mine"}, rules(t, getReport(t, client, "")))
}

func TestSendGivesUpAfterRepeatedConflicts(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	require.NoError(t, d.Send(context.Background(), eventIn("", "first", event.PriorityError)))
	var updates atomic.Int32
	client.PrependReactor("update", "clusterreports", func(k8stesting.Action) (bool, runtime.Object, error) {
		updates.Add(1)
		return true, nil, apierrors.NewConflict(clusterReportsGVR.GroupResource(), reportName, errors.New("secret detail"))
	})
	err := d.Send(context.Background(), eventIn("", "second", event.PriorityError))
	require.Error(t, err)
	assert.Equal(t, int32(maxAttempts), updates.Load())
	assert.Equal(t, "policyreport write report: HTTP 409 Conflict", err.Error())
	assert.True(t, apierrors.IsConflict(err), "the cause stays inspectable")
	assert.NotContains(t, fmt.Sprintf("%v %+v %q", err, err, err), "secret detail")
}

func TestSendFallsBackWhenNamespaceIsMissing(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	client.PrependReactor("create", "reports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() == "ghost" {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "ghost")
		}
		return false, nil, nil
	})
	evt := eventIn("ghost", "r1", event.PriorityError)
	evt.OutputFields["k8s.pod.name"] = "p"
	require.NoError(t, d.Send(context.Background(), evt))

	report := getReport(t, client, "falco")
	assert.Equal(t, []string{"r1"}, rules(t, report))
	results, _, _ := unstructured.NestedSlice(report.Object, "results")
	resources := results[0].(map[string]any)["resources"].([]any)
	assert.Equal(t, "ghost", resources[0].(map[string]any)["namespace"], "the resource keeps its own namespace")
}

func TestSendDoesNotFallBackOnOtherNotFound(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	client.PrependReactor("create", "reports", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(reportsGVR.GroupResource(), reportName)
	})
	err := d.Send(context.Background(), eventIn("prod", "r1", event.PriorityError))
	require.Error(t, err)
	assert.Equal(t, "policyreport write report: HTTP 404 Not Found", err.Error())
	assert.Len(t, client.Actions(), 2, "one get and one create, no fallback")
}

func TestSafeErrorPermanence(t *testing.T) {
	resource := schema.GroupResource{Group: "openreports.io", Resource: "reports"}
	tests := []struct {
		err       error
		name      string
		permanent bool
	}{
		{name: "forbidden", err: apierrors.NewForbidden(resource, "falcosidekick", errors.New("denied")), permanent: true},
		{name: "invalid", err: apierrors.NewBadRequest("invalid report"), permanent: true},
		{name: "conflict", err: apierrors.NewConflict(resource, "falcosidekick", errors.New("changed"))},
		{name: "too many requests", err: apierrors.NewTooManyRequests("slow down", 1)},
		{name: "server error", err: apierrors.NewInternalError(errors.New("boom"))},
		{name: "network", err: fmt.Errorf("dial: %w", syscall.ECONNREFUSED)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.permanent, output.IsPermanent(newDeliveryError(opWriteReport, tt.err)))
		})
	}
}

func TestSendReportsReadErrorsSafely(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	client.PrependReactor("get", "clusterreports", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(clusterReportsGVR.GroupResource(), reportName, errors.New(`User "system:serviceaccount:x" cannot get`))
	})
	err := d.Send(context.Background(), eventIn("", "r1", event.PriorityError))
	require.Error(t, err)
	assert.Equal(t, "policyreport write report: HTTP 403 Forbidden", err.Error())
	assert.NotContains(t, fmt.Sprintf("%v", err), "serviceaccount")
}

func TestSendHonorsCanceledContext(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := d.Send(ctx, eventIn("", "r1", event.PriorityError))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, "policyreport write report: request canceled", err.Error())
	assert.Empty(t, client.Actions())
}

func TestSendSerializesWritesPerReport(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	const workers, perWorker = 8, 10
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range perWorker {
				ns := "a"
				if i%2 == 0 {
					ns = "b"
				}
				assert.NoError(t, d.Send(context.Background(), eventIn(ns, fmt.Sprintf("w%d-%d", w, i), event.PriorityError)))
			}
		})
	}
	wg.Wait()
	assert.Len(t, rules(t, getReport(t, client, "a")), workers*perWorker/2)
	assert.Len(t, rules(t, getReport(t, client, "b")), workers*perWorker/2)
}

// A write waiting for another write to the same report leaves when its context ends.
func TestWriteWaitFollowsTheContext(t *testing.T) {
	d, _ := newFakeDriver(t, nil)
	busy := target{namespace: "falco"}
	stripe := d.stripe(busy)
	require.NoError(t, stripe.Acquire(context.Background(), 1))
	defer stripe.Release(1)
	assert.Same(t, stripe, d.stripe(target{namespace: "falco"}), "a report always maps to one stripe")

	err := testutil.RequireReturnsOnCancel(t, "apply", func(ctx context.Context) error {
		return d.apply(ctx, busy, map[string]any{})
	})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Len(t, d.stripes, writeStripes, "namespaces taken from events never grow the locks")
}

// The pipeline context has no deadline during normal delivery: the client bounds each API request.
func TestRequestTimeoutBoundsAnUnansweredRequest(t *testing.T) {
	server := testutil.HangingHTTPServer(t)
	cfg, err := loadRESTConfig(testutil.WriteKubeconfig(t, server.URL, "", "token"))
	require.NoError(t, err)
	assert.Equal(t, requestTimeout, cfg.Timeout)

	cfg.Timeout = testutil.CancelAfter
	client, err := dynamic.NewForConfig(cfg)
	require.NoError(t, err)
	d := newDriver(&config{MaxResults: defaultMaxResults}, client, nil, nil)
	start := time.Now()
	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Less(t, time.Since(start), testutil.ReturnWithin)
	assert.False(t, output.IsPermanent(err), "a timeout is retried")
}

func TestCreateOutputConfig(t *testing.T) {
	kubeconfig := testutil.WriteKubeconfig(t, "https://127.0.0.1:6443", "", "token")
	tests := []struct {
		raw     map[string]any
		check   func(t *testing.T, d *driver)
		name    string
		wantErr string
	}{
		{
			name: "defaults",
			raw:  map[string]any{"kubeconfig": kubeconfig},
			check: func(t *testing.T, d *driver) {
				assert.Equal(t, defaultMaxResults, d.cfg.MaxResults)
				assert.False(t, d.cfg.PruneByPriority)
				assert.Equal(t, "default", d.fallback)
			},
		},
		{
			name: "explicit values",
			raw:  map[string]any{"kubeconfig": kubeconfig, "max_results": 5, "prune_by_priority": true, "fallback_namespace": "falco"},
			check: func(t *testing.T, d *driver) {
				assert.Equal(t, 5, d.cfg.MaxResults)
				assert.True(t, d.cfg.PruneByPriority)
				assert.Equal(t, "falco", d.fallback)
			},
		},
		{
			name: "runtime override",
			raw:  map[string]any{"kubeconfig": kubeconfig, "runtime": map[string]any{"minimum_priority": "warning"}},
			check: func(t *testing.T, d *driver) {
				assert.Equal(t, event.PriorityWarning, d.RuntimeConfig().MinPriority)
			},
		},
		{name: "zero max_results", raw: map[string]any{"kubeconfig": kubeconfig, "max_results": 0}, wantErr: "max_results: must be at least 1"},
		{name: "negative max_results", raw: map[string]any{"kubeconfig": kubeconfig, "max_results": -1}, wantErr: "max_results"},
		{name: "invalid fallback_namespace", raw: map[string]any{"kubeconfig": kubeconfig, "fallback_namespace": "Not_Valid"}, wantErr: "fallback_namespace: must be a valid namespace name"},
		{name: "max_events is refused", raw: map[string]any{"kubeconfig": kubeconfig, "max_events": 5}, wantErr: "unknown keys: max_events"},
		{name: "falco_namespace is refused", raw: map[string]any{"kubeconfig": kubeconfig, "falco_namespace": "falco"}, wantErr: "unknown keys: falco_namespace"},
		{name: "unknown key", raw: map[string]any{"kubeconfig": kubeconfig, "maxevents": 1}, wantErr: "unknown keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withServiceAccountNamespace(t, filepath.Join(t.TempDir(), "absent"))
			drv, err := OutputType.New(tt.raw, output.Deps{})
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			d := drv.(*driver)
			assert.Equal(t, name, d.Name())
			require.NoError(t, d.Init(context.Background()))
			require.NoError(t, d.Close())
			tt.check(t, d)
		})
	}
}

func TestInitLoadsClientConfiguration(t *testing.T) {
	tests := []struct {
		inCluster func() (*rest.Config, error)
		raw       map[string]any
		name      string
		wantErr   string
	}{
		{
			name:    "missing kubeconfig file",
			raw:     map[string]any{"kubeconfig": filepath.Join(t.TempDir(), "absent")},
			wantErr: "policyreport: kubeconfig: file does not exist",
		},
		{
			name:    "kubeconfig is a FIFO",
			raw:     map[string]any{"kubeconfig": fifo(t)},
			wantErr: "policyreport: kubeconfig: not a regular file",
		},
		{
			name:    "unreadable kubeconfig",
			raw:     map[string]any{"kubeconfig": writeFile(t, "token: hunter2\n: : not yaml")},
			wantErr: "policyreport: kubeconfig: cannot load file",
		},
		{
			name:      "outside a cluster",
			raw:       map[string]any{},
			inCluster: func() (*rest.Config, error) { return nil, rest.ErrNotInCluster },
			wantErr:   "policyreport: kubeconfig: required when not running in a Kubernetes pod",
		},
		{
			name: "in a cluster",
			raw:  map[string]any{},
			inCluster: func() (*rest.Config, error) {
				return &rest.Config{Host: "https://10.0.0.1:443", BearerToken: "token"}, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.inCluster != nil {
				withInClusterConfig(t, tt.inCluster)
			}
			drv, err := OutputType.New(tt.raw, output.Deps{})
			require.NoError(t, err, "client configuration is loaded by Init")
			err = drv.Init(context.Background())
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNotReadyBeforeInit(t *testing.T) {
	drv, err := OutputType.New(map[string]any{}, output.Deps{})
	require.NoError(t, err)
	require.ErrorIs(t, drv.Send(context.Background(), testutil.CreateValidEvent()), core.ErrNotReady)
	require.ErrorIs(t, drv.HealthCheck(context.Background()), core.ErrNotReady)
}

func TestFallbackNamespaceFromPod(t *testing.T) {
	withServiceAccountNamespace(t, writeFile(t, "falco\n"))
	drv, err := OutputType.New(map[string]any{}, output.Deps{})
	require.NoError(t, err)
	assert.Equal(t, "falco", drv.(*driver).fallback)
}

func TestFallbackNamespace(t *testing.T) {
	withServiceAccountNamespace(t, writeFile(t, "security\n"))
	assert.Equal(t, "configured", fallbackNamespace("configured"))
	assert.Equal(t, "security", fallbackNamespace(""))

	withServiceAccountNamespace(t, writeFile(t, "Invalid_NS"))
	assert.Equal(t, "default", fallbackNamespace(""))

	withServiceAccountNamespace(t, filepath.Join(t.TempDir(), "absent"))
	assert.Equal(t, "default", fallbackNamespace(""))
}

func TestOutputTypeSchema(t *testing.T) {
	names := map[string]bool{}
	for _, f := range OutputType.Schema.Fields {
		names[f.Name] = true
		assert.False(t, f.Secret, f.Name)
	}
	for _, want := range []string{"kubeconfig", "fallback_namespace", "max_results", "prune_by_priority", "runtime.minimum_priority"} {
		assert.True(t, names[want], want)
	}
	assert.Equal(t, "policyreport", OutputType.Name)
}

func withServiceAccountNamespace(t *testing.T, path string) {
	t.Helper()
	old := serviceAccountNamespaceFile
	serviceAccountNamespaceFile = path
	t.Cleanup(func() { serviceAccountNamespaceFile = old })
}

func withInClusterConfig(t *testing.T, fn func() (*rest.Config, error)) {
	t.Helper()
	old := inClusterConfig
	inClusterConfig = fn
	t.Cleanup(func() { inClusterConfig = old })
}

func TestKubeconfigRelativePathsResolveFromItsDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ca.pem", "token"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600))
	}
	path := filepath.Join(dir, "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(`apiVersion: v1
kind: Config
current-context: c
clusters: [{name: k, cluster: {server: "https://127.0.0.1:6443", certificate-authority: ca.pem}}]
users: [{name: u, user: {tokenFile: token}}]
contexts: [{name: c, context: {cluster: k, user: u}}]
`), 0o600))
	cfg, err := restConfigFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "ca.pem"), cfg.CAFile)
	assert.Equal(t, filepath.Join(dir, "token"), cfg.BearerTokenFile)
	assert.Equal(t, "https://127.0.0.1:6443", cfg.Host)
}

func fifo(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, syscall.Mkfifo(path, 0o600))
	return path
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}
