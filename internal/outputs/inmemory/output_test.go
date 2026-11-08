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

package inmemory

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func testEvent(rule string, priority event.Priority, source string, t time.Time) *event.Event {
	return &event.Event{
		UUID:         fmt.Sprintf("uuid-%s-%d", rule, t.UnixNano()),
		Output:       fmt.Sprintf("output for %s", rule),
		Priority:     priority,
		Rule:         rule,
		Time:         t,
		OutputFields: map[string]interface{}{"key": "value"},
		Source:       source,
		Tags:         []string{"tag1", "tag2"},
		Hostname:     "node-1",
	}
}

func createTestOutput(capacity int) *driver {
	o, _ := createOutput(map[string]any{
		"capacity":    capacity,
		"ttl":         "0s",
		"gc_interval": "10s",
	}, output.Deps{})
	return o.(*driver)
}

// --- OutputDriver compliance ---

func TestName(t *testing.T) {
	o := createTestOutput(100)
	assert.Equal(t, "inmemory", o.Name())
}

func TestInit(t *testing.T) {
	o := createTestOutput(100)
	assert.NoError(t, o.Init(context.Background()))
	assert.NoError(t, o.Close())
}

func TestHealthCheck(t *testing.T) {
	o := createTestOutput(100)
	assert.NoError(t, o.HealthCheck(context.Background()))
}

func TestCloseIsIdempotent(t *testing.T) {
	o := createTestOutput(100)
	require.NoError(t, o.Init(context.Background()))
	assert.NoError(t, o.Close())
	assert.NoError(t, o.Close(), "second Close must not panic or error")
}

// --- createOutput validation ---

func TestCreateRuntimeDefaults(t *testing.T) {
	o, err := createOutput(map[string]any{}, output.Deps{})
	require.NoError(t, err)
	mem := o.(*driver)
	assert.Equal(t, 10000, mem.capacity)
	assert.Equal(t, time.Duration(0), mem.ttl)
	assert.Equal(t, time.Duration(0), mem.gcInterval)
}

func TestCreateOutputCustomConfig(t *testing.T) {
	o, err := createOutput(map[string]any{
		"capacity":    500,
		"ttl":         "1h",
		"gc_interval": "30s",
	}, output.Deps{})
	require.NoError(t, err)
	mem := o.(*driver)
	assert.Equal(t, 500, mem.capacity)
	assert.Equal(t, time.Hour, mem.ttl)
	assert.Equal(t, 30*time.Second, mem.gcInterval)
}

// --- Send + ReadableStore ---

func TestSendAndSearch(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityError, "syscall", now.Add(time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
	assert.Len(t, result.Events, 2)
	assert.Equal(t, "rule-b", result.Events[0].Rule)
	assert.Equal(t, "rule-a", result.Events[1].Rule)
}

func TestSearchByPriority(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("low", event.PriorityDebug, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("mid", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("high", event.PriorityCritical, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Priority: []string{"warning", "critical"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
	assert.Equal(t, "high", result.Events[0].Rule)
	assert.Equal(t, "mid", result.Events[1].Rule)
}

func TestSearchByRule(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("rule-c", event.PriorityWarning, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Rule: []string{"rule-a", "rule-c"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.Total)
}

func TestSearchBySource(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("r2", event.PriorityWarning, "k8s_audit", now.Add(time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Source: []string{"k8s_audit"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "r2", result.Events[0].Rule)
}

func TestSearchByHostname(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	e1 := testEvent("r1", event.PriorityWarning, "syscall", now)
	e1.Hostname = "node-1"
	e2 := testEvent("r2", event.PriorityWarning, "syscall", now.Add(time.Second))
	e2.Hostname = "node-2"

	require.NoError(t, o.Send(ctx, e1))
	require.NoError(t, o.Send(ctx, e2))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Hostname: []string{"node-2"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "r2", result.Events[0].Rule)
}

func TestSearchByTags(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	e1 := testEvent("r1", event.PriorityWarning, "syscall", now)
	e1.Tags = []string{"filesystem", "mitre"}
	e2 := testEvent("r2", event.PriorityWarning, "syscall", now.Add(time.Second))
	e2.Tags = []string{"network", "dns"}

	require.NoError(t, o.Send(ctx, e1))
	require.NoError(t, o.Send(ctx, e2))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Tags: []string{"network"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "r2", result.Events[0].Rule)
}

func TestSearchByTimeWindow(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	old := time.Now().Add(-2 * time.Hour)
	recent := time.Now().Add(-5 * time.Minute)

	require.NoError(t, o.Send(ctx, testEvent("old", event.PriorityWarning, "syscall", old)))
	require.NoError(t, o.Send(ctx, testEvent("recent", event.PriorityWarning, "syscall", recent)))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{Since: 1 * time.Hour},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "recent", result.Events[0].Rule)
}

func TestSearchFreeText(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	e1 := testEvent("Write below binary dir", event.PriorityError, "syscall", now)
	e1.Output = "File below /usr/bin opened for writing"
	e2 := testEvent("Shell spawned", event.PriorityWarning, "syscall", now.Add(time.Second))
	e2.Output = "Shell spawned in container"

	require.NoError(t, o.Send(ctx, e1))
	require.NoError(t, o.Send(ctx, e2))

	tests := []struct {
		name   string
		filter string
		want   int
	}{
		{"match output", "binary", 1},
		{"match rule", "Shell spawned", 1},
		{"match case insensitive", "BINARY", 1},
		{"no match", "nonexistent", 0},
		{"match both", "syscall", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := o.Search(ctx, &output.SearchQuery{Filters: output.Filters{Filter: tt.filter}})
			require.NoError(t, err)
			assert.Equal(t, int64(tt.want), result.Total)
		})
	}
}

func TestSearchCombinedFilters(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityCritical, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityWarning, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{
			Rule:     []string{"rule-a"},
			Priority: []string{"critical"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "rule-a", result.Events[0].Rule)
	assert.Equal(t, event.PriorityCritical, result.Events[0].Priority)
}

func TestSearchPagination(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	for i := 0; i < 25; i++ {
		require.NoError(t, o.Send(ctx, testEvent(
			fmt.Sprintf("rule-%02d", i), event.PriorityWarning, "syscall", now.Add(time.Duration(i)*time.Second),
		)))
	}

	tests := []struct {
		name      string
		page      int
		limit     int
		wantCount int
		wantTotal int64
	}{
		{"first page", 1, 10, 10, 25},
		{"second page", 2, 10, 10, 25},
		{"third page (partial)", 3, 10, 5, 25},
		{"beyond last page", 4, 10, 0, 25},
		{"maximum page with default-sized limit", math.MaxInt, 100, 0, 25},
		{"maximum page with maximum limit", math.MaxInt, 10000, 0, 25},
		{"exact page boundary", 6, 5, 0, 25},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := o.Search(ctx, &output.SearchQuery{Page: tt.page, Limit: tt.limit})
			require.NoError(t, err)
			assert.Equal(t, tt.wantTotal, result.Total)
			assert.Len(t, result.Events, tt.wantCount)
			assert.Equal(t, tt.page, result.Page)
			assert.Equal(t, tt.limit, result.Limit)
		})
	}
}

func TestCapacityDropsOldest(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(3)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("first", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("second", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("third", event.PriorityWarning, "syscall", now.Add(2*time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("fourth", event.PriorityWarning, "syscall", now.Add(3*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{})
	require.NoError(t, err)
	assert.Equal(t, int64(3), result.Total)

	rules := make([]string, len(result.Events))
	for i, e := range result.Events {
		rules[i] = e.Rule
	}
	assert.NotContains(t, rules, "first")
	assert.Contains(t, rules, "second")
	assert.Contains(t, rules, "third")
	assert.Contains(t, rules, "fourth")
}

func TestCount(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("r2", event.PriorityError, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("r3", event.PriorityCritical, "k8s_audit", now.Add(2*time.Second))))

	tests := []struct {
		filters *output.Filters
		name    string
		want    int64
	}{
		{&output.Filters{}, "all", 3},
		{&output.Filters{Priority: []string{"warning"}}, "by priority", 1},
		{&output.Filters{Source: []string{"k8s_audit"}}, "by source", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := o.Count(ctx, tt.filters)
			require.NoError(t, err)
			assert.Equal(t, tt.want, count)
		})
	}
}

func TestCountHonorsFreeTextFilter(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("exec_bash", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("connect_tcp", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("exec_sh", event.PriorityError, "syscall", now.Add(2*time.Second))))

	count, err := o.Count(ctx, &output.Filters{Filter: "exec"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), count, "Count must honor Filters.Filter free-text substring match")

	count, err = o.Count(ctx, &output.Filters{Filter: "exec", Priority: []string{"error"}})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "Count must AND free-text with structured filters")
}

func TestCountByHonorsFreeTextFilter(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("exec_bash", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("connect_tcp", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("exec_sh", event.PriorityError, "syscall", now.Add(2*time.Second))))

	groups, err := o.CountBy(ctx, "priority", &output.Filters{Filter: "exec"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), groups["warning"])
	assert.Equal(t, int64(1), groups["error"])
	assert.NotContains(t, groups, "notice", "events matching neither filter nor priority must not appear")
}

func TestCountBy(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("r2", event.PriorityWarning, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("r3", event.PriorityCritical, "k8s_audit", now.Add(2*time.Second))))

	tests := []struct {
		want  map[string]int64
		name  string
		field string
	}{
		{map[string]int64{"warning": 2, "critical": 1}, "by priority", "priority"},
		{map[string]int64{"syscall": 2, "k8s_audit": 1}, "by source", "source"},
		{map[string]int64{"r1": 1, "r2": 1, "r3": 1}, "by rule", "rule"},
		{map[string]int64{"node-1": 3}, "by hostname", "hostname"},
		{map[string]int64{"tag1": 3, "tag2": 3}, "by tags", "tags"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := o.CountBy(ctx, tt.field, &output.Filters{})
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestCountByWithFilters(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("r2", event.PriorityWarning, "k8s_audit", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("r3", event.PriorityCritical, "syscall", now.Add(2*time.Second))))

	result, err := o.CountBy(ctx, "priority", &output.Filters{Source: []string{"syscall"}})
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"warning": 1, "critical": 1}, result)
}

func TestCountByInvalidField(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	_, err := o.CountBy(ctx, "invalid", &output.Filters{})
	assert.Error(t, err)
}

func TestEmptyStoreReturnsZero(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	result, err := o.Search(ctx, &output.SearchQuery{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	assert.Empty(t, result.Events)

	count, err := o.Count(ctx, &output.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestTTLExpiry(t *testing.T) {
	ctx := context.Background()
	o, err := createOutput(map[string]any{
		"capacity":    100,
		"ttl":         "100ms",
		"gc_interval": "50ms",
	}, output.Deps{})
	require.NoError(t, err)

	mem := o.(*driver)
	require.NoError(t, mem.Init(ctx))
	defer mem.Close()

	require.NoError(t, mem.Send(ctx, testEvent("r1", event.PriorityWarning, "syscall", time.Now())))

	count, err := mem.Count(ctx, &output.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	time.Sleep(200 * time.Millisecond)

	count, err = mem.Count(ctx, &output.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(1000)

	done := make(chan struct{})

	go func() {
		for i := 0; i < 500; i++ {
			_ = o.Send(ctx, testEvent(
				fmt.Sprintf("rule-%d", i), event.PriorityWarning, "syscall", time.Now(),
			))
		}
		close(done)
	}()

	for i := 0; i < 100; i++ {
		_, _ = o.Search(ctx, &output.SearchQuery{})
		_, _ = o.Count(ctx, &output.Filters{})
		_, _ = o.CountBy(ctx, "priority", &output.Filters{})
	}

	<-done

	count, err := o.Count(ctx, &output.Filters{})
	require.NoError(t, err)
	assert.Equal(t, int64(500), count)
}

func TestSearchCombinedIndexIntersection(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	now := time.Now()
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(ctx, testEvent("rule-a", event.PriorityCritical, "k8s_audit", now.Add(time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityWarning, "syscall", now.Add(2*time.Second))))
	require.NoError(t, o.Send(ctx, testEvent("rule-b", event.PriorityCritical, "k8s_audit", now.Add(3*time.Second))))

	result, err := o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{
			Rule:   []string{"rule-a"},
			Source: []string{"syscall"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "rule-a", result.Events[0].Rule)
	assert.Equal(t, "syscall", result.Events[0].Source)

	result, err = o.Search(ctx, &output.SearchQuery{
		Filters: output.Filters{
			Rule:     []string{"rule-b"},
			Priority: []string{"critical"},
			Source:   []string{"k8s_audit"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Equal(t, "rule-b", result.Events[0].Rule)
}

// --- Interface compliance ---

func TestImplementsOutputDriver(t *testing.T) {
	o := createTestOutput(10)
	var _ output.Driver = o
}

func TestImplementsReadableStore(t *testing.T) {
	o := createTestOutput(10)
	var _ output.ReadableStore = o
}

func TestSearchSortByRule(t *testing.T) {
	o := createTestOutput(100)
	now := time.Now()
	require.NoError(t, o.Send(context.Background(), testEvent("ZZZ_rule", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(context.Background(), testEvent("AAA_rule", event.PriorityError, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(context.Background(), testEvent("MMM_rule", event.PriorityNotice, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(context.Background(), &output.SearchQuery{SortBy: "rule", SortDesc: false})
	require.NoError(t, err)
	require.Len(t, result.Events, 3)
	assert.Equal(t, "AAA_rule", result.Events[0].Rule)
	assert.Equal(t, "ZZZ_rule", result.Events[2].Rule)
}

func TestSearchSortByPriority(t *testing.T) {
	o := createTestOutput(100)
	now := time.Now()
	require.NoError(t, o.Send(context.Background(), testEvent("r1", event.PriorityDebug, "syscall", now)))
	require.NoError(t, o.Send(context.Background(), testEvent("r2", event.PriorityEmergency, "syscall", now.Add(time.Second))))
	require.NoError(t, o.Send(context.Background(), testEvent("r3", event.PriorityWarning, "syscall", now.Add(2*time.Second))))

	result, err := o.Search(context.Background(), &output.SearchQuery{SortBy: "priority", SortDesc: true})
	require.NoError(t, err)
	require.Len(t, result.Events, 3)
	assert.Equal(t, event.PriorityEmergency, result.Events[0].Priority)
	assert.Equal(t, event.PriorityDebug, result.Events[2].Priority)
}

func TestSearchSortAscendingTimestamp(t *testing.T) {
	o := createTestOutput(100)
	now := time.Now()
	require.NoError(t, o.Send(context.Background(), testEvent("r3", event.PriorityWarning, "syscall", now.Add(2*time.Second))))
	require.NoError(t, o.Send(context.Background(), testEvent("r1", event.PriorityWarning, "syscall", now)))
	require.NoError(t, o.Send(context.Background(), testEvent("r2", event.PriorityWarning, "syscall", now.Add(time.Second))))

	result, err := o.Search(context.Background(), &output.SearchQuery{SortBy: "timestamp", SortDesc: false})
	require.NoError(t, err)
	require.Len(t, result.Events, 3)
	assert.True(t, result.Events[0].Time.Before(result.Events[2].Time), "ascending: oldest first")
}

// --- GetEvent ---

func TestGetEventHit(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)
	now := time.Now()
	evt := testEvent("rule-a", event.PriorityWarning, "syscall", now)
	evt.UUID = "abc-123"
	require.NoError(t, o.Send(ctx, evt))

	got, err := o.GetEvent(ctx, "abc-123")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "abc-123", got.UUID)
	assert.Equal(t, "rule-a", got.Rule)
}

func TestGetEventReturnsCopy(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)
	evt := testEvent("rule-a", event.PriorityWarning, "syscall", time.Now())
	evt.UUID = "copy-me"
	require.NoError(t, o.Send(ctx, evt))

	got, err := o.GetEvent(ctx, "copy-me")
	require.NoError(t, err)
	require.NotNil(t, got)
	got.Rule = "mutated"

	again, err := o.GetEvent(ctx, "copy-me")
	require.NoError(t, err)
	require.NotNil(t, again)
	assert.Equal(t, "rule-a", again.Rule, "GetEvent must return a copy; store state must not be mutable by the caller")
}

func TestGetEventMiss(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)

	got, err := o.GetEvent(ctx, "does-not-exist")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestGetEventEmptyUUID(t *testing.T) {
	o := createTestOutput(100)

	got, err := o.GetEvent(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, output.ErrEmptyUUID)
	assert.Nil(t, got)
}

func TestGetEventAfterRingBufferOverwrite(t *testing.T) {
	const (
		uuid1 = "e1"
		uuid2 = "e2"
		uuid3 = "e3"
	)
	ctx := context.Background()
	o := createTestOutput(2) // tiny capacity
	now := time.Now()

	e1 := testEvent("rule-1", event.PriorityWarning, "syscall", now)
	e1.UUID = uuid1
	e2 := testEvent("rule-2", event.PriorityWarning, "syscall", now.Add(time.Second))
	e2.UUID = uuid2
	e3 := testEvent("rule-3", event.PriorityWarning, "syscall", now.Add(2*time.Second))
	e3.UUID = uuid3

	require.NoError(t, o.Send(ctx, e1))
	require.NoError(t, o.Send(ctx, e2))
	require.NoError(t, o.Send(ctx, e3)) // overwrites e1

	got, err := o.GetEvent(ctx, uuid1)
	require.NoError(t, err)
	assert.Nil(t, got, "event evicted from the ring buffer must return (nil, nil)")

	got, err = o.GetEvent(ctx, uuid3)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uuid3, got.UUID)
}

// --- Filter combination semantics (contract) ---

// Contract: within a field multiple values combine with OR,
// across fields criteria combine with AND. Enforced across every ReadableStore.
func TestFilterSemanticsWithinFieldOrCrossFieldAnd(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)
	now := time.Now()

	// e1: priority=error, rule=foo
	e1 := testEvent("foo", event.PriorityError, "syscall", now)
	e1.UUID = "e1"
	// e2: priority=critical, rule=foo
	e2 := testEvent("foo", event.PriorityCritical, "syscall", now.Add(time.Second))
	e2.UUID = "e2"
	// e3: priority=error, rule=bar
	e3 := testEvent("bar", event.PriorityError, "syscall", now.Add(2*time.Second))
	e3.UUID = "e3"
	// e4: priority=warning, rule=foo
	e4 := testEvent("foo", event.PriorityWarning, "syscall", now.Add(3*time.Second))
	e4.UUID = "e4"

	for _, e := range []*event.Event{e1, e2, e3, e4} {
		require.NoError(t, o.Send(ctx, e))
	}

	tests := []struct {
		name     string
		wantUUID []string
		filters  output.Filters
	}{
		{
			name:     "single-value: priority=error (within-field, single)",
			filters:  output.Filters{Priority: []string{"error"}},
			wantUUID: []string{"e1", "e3"},
		},
		{
			name:     "multi-value: priority=error,critical (within-field OR)",
			filters:  output.Filters{Priority: []string{"error", "critical"}},
			wantUUID: []string{"e1", "e2", "e3"},
		},
		{
			name:     "cross-field: priority=error AND rule=foo (across-field AND)",
			filters:  output.Filters{Priority: []string{"error"}, Rule: []string{"foo"}},
			wantUUID: []string{"e1"},
		},
		{
			name:     "cross-field with multi-value: priority=error,critical AND rule=foo",
			filters:  output.Filters{Priority: []string{"error", "critical"}, Rule: []string{"foo"}},
			wantUUID: []string{"e1", "e2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := o.Search(ctx, &output.SearchQuery{Filters: tt.filters})
			require.NoError(t, err)

			got := make([]string, 0, len(result.Events))
			for _, e := range result.Events {
				got = append(got, e.UUID)
			}
			assert.ElementsMatch(t, tt.wantUUID, got)
		})
	}
}

func TestHistogramDenseBuckets(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)
	now := time.Now()

	require.NoError(t, o.Send(ctx, testEvent("r", event.PriorityWarning, "syscall", now.Add(-50*time.Minute))))
	require.NoError(t, o.Send(ctx, testEvent("r", event.PriorityWarning, "syscall", now.Add(-20*time.Minute))))
	require.NoError(t, o.Send(ctx, testEvent("r", event.PriorityWarning, "syscall", now.Add(-5*time.Minute))))
	require.NoError(t, o.Send(ctx, testEvent("r", event.PriorityWarning, "syscall", now.Add(-1*time.Minute))))

	res, err := o.Histogram(ctx, &output.HistogramRequest{
		Filters:  output.Filters{Since: time.Hour},
		BucketMs: (10 * time.Minute).Milliseconds(),
	})
	require.NoError(t, err)
	require.Len(t, res.Buckets, 6, "1h / 10min = 6 dense buckets")
	assert.Equal(t, (10 * time.Minute).Milliseconds(), res.BucketMs)
	assert.Equal(t, res.From+int64(6)*res.BucketMs, res.To)

	var total int64
	for _, b := range res.Buckets {
		total += b.Count
	}
	assert.Equal(t, int64(4), total, "all four events land in the window")
	assert.Nil(t, res.Buckets[0].By, "no group_by -> no per-group map")
}

func TestHistogramExcludesOutOfWindow(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)
	now := time.Now()

	require.NoError(t, o.Send(ctx, testEvent("old", event.PriorityWarning, "syscall", now.Add(-2*time.Hour))))
	require.NoError(t, o.Send(ctx, testEvent("in1", event.PriorityWarning, "syscall", now.Add(-20*time.Minute))))
	require.NoError(t, o.Send(ctx, testEvent("in2", event.PriorityWarning, "syscall", now.Add(-1*time.Minute))))

	res, err := o.Histogram(ctx, &output.HistogramRequest{
		Filters:  output.Filters{Since: time.Hour},
		BucketMs: (15 * time.Minute).Milliseconds(),
	})
	require.NoError(t, err)

	var total int64
	for _, b := range res.Buckets {
		total += b.Count
	}
	assert.Equal(t, int64(2), total, "event older than since must be excluded")
}

func TestHistogramGroupByAllFields(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)
	now := time.Now()

	e1 := testEvent("rule-a", event.PriorityError, "syscall", now.Add(-5*time.Minute))
	e1.Hostname = "node-alpha"
	e1.Tags = []string{"net", "fs"}
	require.NoError(t, o.Send(ctx, e1))

	e2 := testEvent("rule-b", event.PriorityWarning, "k8s_audit", now.Add(-10*time.Minute))
	e2.Hostname = "node-beta"
	e2.Tags = []string{"net"}
	require.NoError(t, o.Send(ctx, e2))

	for _, field := range []string{fieldPriority, fieldRule, fieldSource, fieldHostname, fieldTags} {
		t.Run(field, func(t *testing.T) {
			res, err := o.Histogram(ctx, &output.HistogramRequest{
				Filters:  output.Filters{Since: time.Hour},
				BucketMs: time.Hour.Milliseconds(),
				GroupBy:  field,
			})
			require.NoError(t, err)
			require.Len(t, res.Buckets, 1)
			assert.Equal(t, field, res.GroupBy)

			by := res.Buckets[0].By
			require.NotNil(t, by)
			switch field {
			case fieldPriority:
				assert.Equal(t, int64(1), by["error"])
				assert.Equal(t, int64(1), by["warning"])
			case fieldRule:
				assert.Equal(t, int64(1), by["rule-a"])
				assert.Equal(t, int64(1), by["rule-b"])
			case fieldSource:
				assert.Equal(t, int64(1), by["syscall"])
				assert.Equal(t, int64(1), by["k8s_audit"])
			case fieldHostname:
				assert.Equal(t, int64(1), by["node-alpha"])
				assert.Equal(t, int64(1), by["node-beta"])
			case fieldTags:
				assert.Equal(t, int64(2), by["net"], "tags contributes to every matching key")
				assert.Equal(t, int64(1), by["fs"])
			}
		})
	}
}

func TestHistogramHonorsFilters(t *testing.T) {
	ctx := context.Background()
	o := createTestOutput(100)
	now := time.Now()

	e1 := testEvent("rule-a", event.PriorityError, "syscall", now.Add(-5*time.Minute))
	e1.UUID = "keep"
	require.NoError(t, o.Send(ctx, e1))

	e2 := testEvent("rule-a", event.PriorityWarning, "syscall", now.Add(-5*time.Minute))
	e2.UUID = "drop"
	require.NoError(t, o.Send(ctx, e2))

	res, err := o.Histogram(ctx, &output.HistogramRequest{
		Filters:  output.Filters{Since: time.Hour, Priority: []string{"error"}},
		BucketMs: time.Hour.Milliseconds(),
	})
	require.NoError(t, err)
	require.Len(t, res.Buckets, 1)
	assert.Equal(t, int64(1), res.Buckets[0].Count, "priority filter applied")
}

func TestTagAggregationsCountEachEventOnce(t *testing.T) {
	for _, tc := range []struct {
		want map[string]int64
		name string
		tags []string
	}{
		{name: "no tags", want: map[string]int64{}},
		{name: "distinct tags", tags: []string{"security", "network"}, want: map[string]int64{"security": 1, "network": 1}},
		{name: "duplicate tags", tags: []string{"security", "security", "network", "security"}, want: map[string]int64{"security": 1, "network": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := createTestOutput(10)
			e := testEvent("rule", event.PriorityWarning, "syscall", time.Now().Add(-time.Minute))
			e.Tags = append([]string(nil), tc.tags...)
			require.NoError(t, o.Send(t.Context(), e))
			for _, filters := range []output.Filters{{}, {Since: time.Hour}, {Source: []string{"syscall"}}} {
				counts, err := o.CountBy(t.Context(), "tags", &filters)
				require.NoError(t, err)
				assert.Equal(t, tc.want, counts)
			}
			histogram, err := o.Histogram(t.Context(), &output.HistogramRequest{
				Filters: output.Filters{Since: time.Hour}, BucketMs: time.Hour.Milliseconds(), GroupBy: "tags",
			})
			require.NoError(t, err)
			require.Len(t, histogram.Buckets, 1)
			assert.Equal(t, int64(1), histogram.Buckets[0].Count)
			assert.Equal(t, tc.want, histogram.Buckets[0].By)
			assert.Equal(t, tc.tags, e.Tags, "aggregation must not mutate shared events")
		})
	}
}

func TestTagAggregationsKeepDistinctEvents(t *testing.T) {
	o := createTestOutput(10)
	for range 2 {
		e := testEvent("rule", event.PriorityWarning, "syscall", time.Now().Add(-time.Minute))
		e.Tags = []string{"security", "security"}
		require.NoError(t, o.Send(t.Context(), e))
	}
	for _, filters := range []output.Filters{{}, {Since: time.Hour}, {Source: []string{"syscall"}}} {
		counts, err := o.CountBy(t.Context(), "tags", &filters)
		require.NoError(t, err)
		assert.Equal(t, map[string]int64{"security": 2}, counts)
	}
	histogram, err := o.Histogram(t.Context(), &output.HistogramRequest{
		Filters: output.Filters{Since: time.Hour}, BucketMs: time.Hour.Milliseconds(), GroupBy: "tags",
	})
	require.NoError(t, err)
	require.Len(t, histogram.Buckets, 1)
	assert.Equal(t, int64(2), histogram.Buckets[0].Count)
	assert.Equal(t, map[string]int64{"security": 2}, histogram.Buckets[0].By)
}

func TestHistogramEmptyStore(t *testing.T) {
	o := createTestOutput(100)
	res, err := o.Histogram(context.Background(), &output.HistogramRequest{
		Filters:  output.Filters{Since: time.Hour},
		BucketMs: (15 * time.Minute).Milliseconds(),
	})
	require.NoError(t, err)
	require.Len(t, res.Buckets, 4)
	for _, b := range res.Buckets {
		assert.Zero(t, b.Count)
		assert.Nil(t, b.By)
	}
}

func TestHistogramValidationRejectsBadInput(t *testing.T) {
	o := createTestOutput(100)
	tests := []struct {
		name string
		req  output.HistogramRequest
	}{
		{"missing since", output.HistogramRequest{BucketMs: 60_000}},
		{"zero bucket", output.HistogramRequest{Filters: output.Filters{Since: time.Hour}}},
		{"bucket too small", output.HistogramRequest{Filters: output.Filters{Since: time.Hour}, BucketMs: 10}},
		{"bucket larger than since", output.HistogramRequest{Filters: output.Filters{Since: time.Minute}, BucketMs: time.Hour.Milliseconds()}},
		{"too many buckets", output.HistogramRequest{Filters: output.Filters{Since: time.Hour}, BucketMs: time.Second.Milliseconds()}},
		{"invalid group_by", output.HistogramRequest{Filters: output.Filters{Since: time.Hour}, BucketMs: (15 * time.Minute).Milliseconds(), GroupBy: "uuid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := o.Histogram(context.Background(), &tt.req)
			assert.Error(t, err)
		})
	}
}
