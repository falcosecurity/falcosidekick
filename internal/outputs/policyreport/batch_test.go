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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"

	appconfig "github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

// reportKey names a report in the fake client's actions: "" is the ClusterReport.
func reportKey(action k8stesting.Action) string {
	if action.GetResource().Resource == clusterReportsGVR.Resource {
		return "cluster"
	}
	return action.GetNamespace()
}

// verbsByReport counts the get, create and update actions of each report.
func verbsByReport(client *fake.FakeDynamicClient) map[string]map[string]int {
	counts := map[string]map[string]int{}
	for _, action := range client.Actions() {
		key := reportKey(action)
		if counts[key] == nil {
			counts[key] = map[string]int{}
		}
		counts[key][action.GetVerb()]++
	}
	return counts
}

func writes(client *fake.FakeDynamicClient) int {
	n := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" || action.GetVerb() == "update" {
			n++
		}
	}
	return n
}

func encodedSize(t *testing.T, obj *unstructured.Unstructured) int {
	t.Helper()
	b, err := json.Marshal(obj.Object)
	require.NoError(t, err)
	return len(b)
}

// spread returns n events over three namespaces and the cluster report.
func spread(n int) []*event.Event {
	namespaces := []string{"a", "b", "c", ""}
	events := make([]*event.Event, n)
	for i := range events {
		ns := namespaces[i%len(namespaces)]
		events[i] = eventIn(ns, fmt.Sprintf("%s-%d", ns, i), event.PriorityError)
	}
	return events
}

func TestSendBatchWritesEachReportOnce(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	ctx := context.Background()
	const n = 200
	require.NoError(t, d.SendBatch(ctx, spread(n)))
	assert.Equal(t, map[string]map[string]int{
		"a": {"get": 1, "create": 1}, "b": {"get": 1, "create": 1}, "c": {"get": 1, "create": 1}, "cluster": {"get": 1, "create": 1},
	}, verbsByReport(client))

	client.ClearActions()
	require.NoError(t, d.SendBatch(ctx, spread(n)))
	assert.Equal(t, map[string]map[string]int{
		"a": {"get": 1, "update": 1}, "b": {"get": 1, "update": 1}, "c": {"get": 1, "update": 1}, "cluster": {"get": 1, "update": 1},
	}, verbsByReport(client), "N events cost one read and one write per report, whatever N")

	for first, ns := range []string{"a", "b", "c", ""} {
		got := rules(t, getReport(t, client, ns))
		require.Len(t, got, n/2)
		assert.Equal(t, fmt.Sprintf("%s-%d", ns, first), got[0], "batch order is kept")
		assert.Equal(t, fmt.Sprintf("%s-%d", ns, n-4+first), got[len(got)-1])
	}
}

func TestSendBatchSkipsUnchangedReport(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	ctx := context.Background()
	batch := spread(40)
	require.NoError(t, d.SendBatch(ctx, batch))
	client.ClearActions()

	require.NoError(t, d.SendBatch(ctx, batch), "the pipeline resends a batch whose answer was lost")
	require.NoError(t, d.SendBatch(ctx, batch[:3]))
	assert.Zero(t, writes(client), "a batch of results the reports already hold writes nothing")
	assert.Len(t, client.Actions(), 4+3, "one read per report")

	// A change of max_results alone is a change.
	d.cfg.MaxResults = 5
	require.NoError(t, d.SendBatch(ctx, batch[:1]))
	assert.Equal(t, 1, writes(client))
	assert.Len(t, rules(t, getReport(t, client, "a")), 5)
}

func TestSendBatchAddsDuplicatesOnce(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	evt := eventIn("a", "r1", event.PriorityError)
	other := eventIn("a", "r2", event.PriorityError)
	require.NoError(t, d.SendBatch(context.Background(), []*event.Event{evt, other, evt, evt}))
	assert.Equal(t, []string{"r1", "r2"}, rules(t, getReport(t, client, "a")))
}

func TestSendBatchRetryAfterPartialFailureAddsEachResultOnce(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	ctx := context.Background()
	require.NoError(t, d.SendBatch(ctx, spread(8)))

	failB := true
	client.PrependReactor("update", "reports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() == "b" && failB {
			failB = false
			return true, nil, apierrors.NewInternalError(errors.New("etcd timeout"))
		}
		return false, nil, nil
	})
	batch := spread(8)
	err := d.SendBatch(ctx, batch)
	require.Error(t, err)
	assert.False(t, output.IsPermanent(err), "a server error is retried by the pipeline")

	client.ClearActions()
	require.NoError(t, d.SendBatch(ctx, batch), "pipeline retry")
	assert.Equal(t, map[string]map[string]int{
		"cluster": {"get": 1}, "a": {"get": 1}, "b": {"get": 1, "update": 1}, "c": {"get": 1, "update": 1},
	}, verbsByReport(client), "reports are written in name order: the cluster report and a hold the results, c was never reached")
	for _, ns := range []string{"a", "b", "c", ""} {
		assert.Len(t, rules(t, getReport(t, client, ns)), 4, ns)
	}
}

func TestSendBatchSummaryCountsKeptResults(t *testing.T) {
	d, client := newFakeDriver(t, func(c *config) { c.MaxResults = 4 })
	priorities := []event.Priority{
		event.PriorityCritical, event.PriorityError, event.PriorityWarning, event.PriorityNotice, event.PriorityError, event.PriorityWarning,
	}
	batch := make([]*event.Event, 0, len(priorities))
	for _, p := range priorities {
		batch = append(batch, eventIn("a", string(p), p))
	}
	require.NoError(t, d.SendBatch(context.Background(), batch))
	report := getReport(t, client, "a")
	assert.Equal(t, []string{"warning", "notice", "error", "warning"}, rules(t, report))
	summary, _, _ := unstructured.NestedMap(report.Object, "summary")
	assert.Equal(t, map[string]any{"pass": int64(0), "fail": int64(1), "warn": int64(3), "error": int64(0), "skip": int64(0)}, summary)
	limit, _, _ := unstructured.NestedInt64(report.Object, "configuration", "limits", "maxResults")
	assert.Equal(t, int64(4), limit)
}

// bigEvent carries a message of size bytes, as k8saudit events with large request objects do.
func bigEvent(ns, rule string, p event.Priority, size int) *event.Event {
	evt := eventIn(ns, rule, p)
	evt.Output = strings.Repeat("x", size)
	return evt
}

func TestSendBatchKeepsReportWithinByteLimit(t *testing.T) {
	for _, prune := range []bool{false, true} {
		t.Run(fmt.Sprintf("prune_by_priority=%t", prune), func(t *testing.T) {
			d, client := newFakeDriver(t, func(c *config) { c.PruneByPriority = prune })
			batch := make([]*event.Event, 0, 12)
			for i := range 12 {
				p := event.PriorityError
				if i == 9 {
					p = event.PriorityNotice
				}
				batch = append(batch, bigEvent("a", fmt.Sprintf("r%d", i), p, 100<<10))
			}
			// Two flushes: the second prunes results the report already holds.
			require.NoError(t, d.SendBatch(context.Background(), batch[:6]))
			require.NoError(t, d.SendBatch(context.Background(), batch[6:]))

			report := getReport(t, client, "a")
			size := encodedSize(t, report)
			assert.LessOrEqual(t, size, maxReportBytes)
			got := rules(t, report)
			want := []string{"r7", "r8", "r9", "r10", "r11"}
			if prune {
				want = []string{"r6", "r7", "r8", "r10", "r11"}
			}
			require.Equal(t, want, got, "oldest, or lowest severity, removed first")

			// The limit removes no more than it must: one more result would not fit.
			next, err := buildResult(batch[5])
			require.NoError(t, err)
			results, _, _ := unstructured.NestedSlice(report.Object, "results")
			report.Object["results"] = append([]any{next}, results...)
			assert.Greater(t, encodedSize(t, report), maxReportBytes)

			summary, _, _ := unstructured.NestedMap(getReport(t, client, "a").Object, "summary")
			fails := int64(5)
			if !prune {
				fails = 4
			}
			assert.Equal(t, fails, summary["fail"], "the summary counts the kept results")
		})
	}
}

func TestSendBatchRefusesOnlyTheResultTooLarge(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	batch := []*event.Event{
		eventIn("a", "small", event.PriorityError),
		bigEvent("z", "huge", event.PriorityError, maxReportBytes),
		eventIn("", "small", event.PriorityError),
	}
	err := d.SendBatch(context.Background(), batch)
	require.Error(t, err)
	assert.Equal(t, "policyreport result: 1 of 3 results cannot fit within the 524288-byte report limit", err.Error())
	assert.True(t, output.IsPermanent(err), "a retry cannot shrink the result")
	rejected, retryable, ok := output.PartialEvents(err, len(batch))
	require.True(t, ok, "the error names the oversized event")
	assert.Equal(t, []int{1}, rejected)
	assert.Empty(t, retryable)
	assert.Equal(t, []string{"small"}, rules(t, getReport(t, client, "a")))
	assert.Equal(t, []string{"small"}, rules(t, getReport(t, client, "")))
	assert.Empty(t, verbsByReport(client)["z"], "the oversized result's report is not touched")

	// A batch of oversized results writes nothing and fails every event.
	client.ClearActions()
	err = d.SendBatch(context.Background(), batch[1:2])
	assert.Equal(t, "policyreport result: cannot fit within the 524288-byte report limit", err.Error())
	_, _, ok = output.PartialEvents(err, 1)
	assert.False(t, ok, "the whole batch fails")
	assert.Empty(t, client.Actions(), "nothing is written")

	// The largest result that fits alone is written.
	fits := bigEvent("z", "fits", event.PriorityError, maxReportBytes-4096)
	require.NoError(t, d.SendBatch(context.Background(), []*event.Event{fits}))
	assert.Equal(t, []string{"fits"}, rules(t, getReport(t, client, "z")))
}

// Another writer grew the metadata so that the only result does not fit.
func TestMergeKeepsAtLeastOneResult(t *testing.T) {
	obj := newReport(target{namespace: "a"})
	obj.SetAnnotations(map[string]string{"other-writer": strings.Repeat("y", maxReportBytes-1024)})
	_, err := merge(obj, []map[string]any{{"policy": "p", "message": strings.Repeat("x", 2048)}}, 10, false)
	assert.ErrorIs(t, err, errResultTooLarge)
}

func TestApplyBacksOffOnConflict(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	var (
		mu     sync.Mutex
		sleeps []time.Duration
	)
	d.sleep = func(_ context.Context, wait time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		sleeps = append(sleeps, wait)
		return nil
	}
	require.NoError(t, d.SendBatch(context.Background(), spread(8)))

	conflicts := 2
	client.PrependReactor("update", "reports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() == "b" && conflicts > 0 {
			conflicts--
			return true, nil, apierrors.NewConflict(reportsGVR.GroupResource(), reportName, errors.New("modified"))
		}
		return false, nil, nil
	})
	client.ClearActions()
	require.NoError(t, d.SendBatch(context.Background(), spread(8)), "the conflict is settled within the batch")
	assert.Equal(t, map[string]map[string]int{
		"a": {"get": 1, "update": 1}, "b": {"get": 3, "update": 3}, "c": {"get": 1, "update": 1}, "cluster": {"get": 1, "update": 1},
	}, verbsByReport(client), "only the conflicting report is read again")
	require.Len(t, sleeps, 2)
	assert.InDelta(t, 10*time.Millisecond, sleeps[0], float64(2*time.Millisecond))
	assert.InDelta(t, 50*time.Millisecond, sleeps[1], float64(6*time.Millisecond))
	assert.Len(t, rules(t, getReport(t, client, "b")), 4)
}

func TestApplyBackoffFollowsTheContext(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	d.sleep = sleepContext
	require.NoError(t, d.SendBatch(context.Background(), spread(1)))
	client.PrependReactor("update", "reports", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(reportsGVR.GroupResource(), reportName, errors.New("modified"))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := d.SendBatch(ctx, []*event.Event{eventIn("a", "r", event.PriorityError)})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), time.Second, "the 1.25s backoff step is cut short")
}

func TestSendBatchFallsBackOnceForMissingNamespaces(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	client.PrependReactor("create", "reports", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if ns := action.GetNamespace(); ns == "ghost1" || ns == "ghost2" {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, ns)
		}
		return false, nil, nil
	})
	batch := []*event.Event{
		eventIn("falco", "own", event.PriorityError),
		eventIn("ghost1", "g1", event.PriorityError),
		eventIn("ghost2", "g2", event.PriorityError),
	}
	require.NoError(t, d.SendBatch(context.Background(), batch))
	assert.Equal(t, map[string]int{"get": 1, "create": 1}, verbsByReport(client)["falco"], "the fallback report is written once")
	assert.Equal(t, []string{"own", "g1", "g2"}, rules(t, getReport(t, client, "falco")))
}

func TestPipelineWritesPerReportFollowTheFlush(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	const flush = 100 * time.Millisecond
	cfg := output.RuntimeConfig{
		QueueSize: 10000, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 1, ResetTimeout: time.Second},
		Batching:       &output.BatchingConfig{Enabled: new(true), BatchSize: 10000, FlushInterval: flush},
	}
	out := pipeline.NewOutput(d, &cfg, nil)
	start := time.Now()
	out.Start(context.Background())

	const events = 4000
	for i, evt := range spread(events) {
		out.Enqueue(evt)
		if i%100 == 99 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, out.Retire(ctx))
	elapsed := time.Since(start)

	status := out.GetStatus()
	require.Equal(t, events, status.SentTotal)
	maxWrites := int(elapsed/flush) + 2
	for report, verbs := range verbsByReport(client) {
		assert.LessOrEqual(t, verbs["create"]+verbs["update"], maxWrites, "%s: %d events, at most one write per flush", report, events/4)
	}
	for _, ns := range []string{"a", "b", "c", ""} {
		report := getReport(t, client, ns)
		assert.NotEmpty(t, rules(t, report))
		assert.LessOrEqual(t, encodedSize(t, report), maxReportBytes)
	}
}

func TestPipelineCountsOnlyTheOversizedEventAsFailed(t *testing.T) {
	d, client := newFakeDriver(t, nil)
	cfg := output.RuntimeConfig{
		QueueSize: 100, Workers: 1,
		Retry:          &output.RetryConfig{MaxAttempts: 3, InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, Multiplier: 1},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 1, ResetTimeout: time.Second},
		Batching:       &output.BatchingConfig{Enabled: new(true), BatchSize: 4, FlushInterval: time.Hour},
	}
	out := pipeline.NewOutput(d, &cfg, nil)
	out.Start(context.Background())
	for _, evt := range []*event.Event{
		eventIn("a", "one", event.PriorityError),
		eventIn("a", "two", event.PriorityError),
		bigEvent("a", "huge", event.PriorityError, maxReportBytes),
		eventIn("b", "three", event.PriorityError),
	} {
		out.Enqueue(evt)
	}
	require.Eventually(t, func() bool {
		s := out.GetStatus()
		return s.SentTotal+s.FailedTotal == 4
	}, 5*time.Second, time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, out.Retire(ctx))

	status := out.GetStatus()
	assert.Equal(t, 3, status.SentTotal)
	assert.Equal(t, 1, status.FailedTotal)
	assert.Empty(t, status.LastError, "the batch was delivered")
	assert.Equal(t, pipeline.HealthDegraded, status.Status)
	assert.Equal(t, pipeline.WarningDestination, status.WarningKind)
	assert.Contains(t, status.LastWarning, "1 of 4 results cannot fit")
	assert.Equal(t, 1, verbsByReport(client)["a"]["create"], "a rejection is not retried")
	assert.ElementsMatch(t, []string{"one", "two"}, rules(t, getReport(t, client, "a")))
}

func TestBatchingInheritsRuntimeDefaults(t *testing.T) {
	defaults := output.RuntimeConfig{
		QueueSize: 1000, Workers: 2,
		Retry:          &output.RetryConfig{MaxAttempts: 3, InitialInterval: time.Second, MaxInterval: 30 * time.Second, Multiplier: 2},
		CircuitBreaker: &output.CircuitBreakerConfig{FailureThreshold: 5, SuccessThreshold: 2, ResetTimeout: 30 * time.Second},
		Batching:       &output.BatchingConfig{BatchSize: 500, FlushInterval: time.Second},
	}
	for _, tt := range []struct {
		runtime map[string]any
		name    string
		want    output.BatchingConfig
	}{
		{name: "omitted", want: output.BatchingConfig{Enabled: new(true), BatchSize: 500, FlushInterval: time.Second}},
		{
			name:    "flush interval set",
			runtime: map[string]any{"batching": map[string]any{"flush_interval": "2s"}},
			want:    output.BatchingConfig{Enabled: new(true), BatchSize: 500, FlushInterval: 2 * time.Second},
		},
		{
			name:    "disabled",
			runtime: map[string]any{"batching": map[string]any{"enabled": false}},
			want:    output.BatchingConfig{Enabled: new(false), BatchSize: 500, FlushInterval: time.Second},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := map[string]any{}
			if tt.runtime != nil {
				raw["runtime"] = tt.runtime
			}
			drv, err := OutputType.New(raw, output.Deps{})
			require.NoError(t, err)
			merged, err := appconfig.MergeRuntimeConfig(defaults, name, drv.(*driver).RuntimeConfig())
			require.NoError(t, err)
			assert.Equal(t, tt.want, *merged.Batching)
		})
	}
}

func BenchmarkSendBatch(b *testing.B) {
	cfg := config{MaxResults: defaultMaxResults, FallbackNamespace: "falco"}
	d := newDriver(&cfg, newFakeClient(), nil)
	batch := spread(500)
	b.ReportAllocs()
	for b.Loop() {
		for _, evt := range batch {
			evt.UUID = fmt.Sprintf("%s-%d", evt.UUID[:24], eventSeq.Add(1))
		}
		if err := d.SendBatch(context.Background(), batch); err != nil {
			b.Fatal(err)
		}
	}
}
