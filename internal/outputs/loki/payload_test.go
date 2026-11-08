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

package loki

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

// The stream labels are few and bounded: rule, tags and output fields stay in the log line.
func TestBuildPayloadLabels(t *testing.T) {
	evt := testutil.CreateValidEvent()
	payload := buildPayload(formatJSON, nil, evt)

	require.Len(t, payload.Streams, 1)
	assert.Equal(t, map[string]string{
		"source":   "syscall",
		"priority": "Error",
		"level":    "error",
		"hostname": "node-1",
	}, payload.Streams[0].Stream)

	var line map[string]any
	require.NoError(t, json.Unmarshal([]byte(payload.Streams[0].Values[0][1]), &line))
	assert.Equal(t, evt.Rule, line["rule"])
	assert.Equal(t, []any{"filesystem", "mitre_persistence"}, line["tags"])
}

// level uses the names Grafana colors: critical, error, warning, info, debug.
func TestBuildPayloadLevel(t *testing.T) {
	for _, tc := range []struct {
		priority      event.Priority
		priorityLabel string
		level         string
	}{
		{event.PriorityEmergency, "Emergency", "critical"},
		{event.PriorityAlert, "Alert", "critical"},
		{event.PriorityCritical, "Critical", "critical"},
		{event.PriorityError, "Error", "error"},
		{event.PriorityWarning, "Warning", "warning"},
		{event.PriorityNotice, "Notice", "info"},
		{event.PriorityInformational, "Informational", "info"},
		{event.PriorityDebug, "Debug", "debug"},
	} {
		t.Run(string(tc.priority), func(t *testing.T) {
			evt := testutil.CreateValidEvent()
			evt.Priority = tc.priority
			labels := buildPayload(formatJSON, nil, evt).Streams[0].Stream
			assert.Equal(t, tc.priorityLabel, labels["priority"])
			assert.Equal(t, tc.level, labels["level"])
		})
	}
}

func TestBuildPayloadTimestamp(t *testing.T) {
	evt := testutil.CreateValidEvent()
	payload := buildPayload(formatJSON, nil, evt)

	ts := payload.Streams[0].Values[0][0]
	expected := strconv.FormatInt(evt.Time.UnixNano(), 10)
	assert.Equal(t, expected, ts)
}

func TestBuildPayloadJSONFormat(t *testing.T) {
	evt := testutil.CreateValidEvent()
	payload := buildPayload(formatJSON, nil, evt)

	line := payload.Streams[0].Values[0][1]
	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(line), &decoded))
	assert.Equal(t, evt.Rule, decoded["rule"])
}

func TestBuildPayloadTextFormat(t *testing.T) {
	evt := testutil.CreateValidEvent()
	payload := buildPayload("text", nil, evt)

	line := payload.Streams[0].Values[0][1]
	assert.Equal(t, evt.Output, line)
}

// The namespace is a label; the pod, one stream per pod, stays in the log line.
func TestBuildPayloadK8sFields(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.OutputFields["k8s.ns.name"] = "default"
	evt.OutputFields["k8s.pod.name"] = "nginx-abc"

	payload := buildPayload(formatJSON, nil, evt)
	labels := payload.Streams[0].Stream
	assert.Equal(t, "default", labels["k8s_ns_name"])
	assert.NotContains(t, labels, "k8s_pod_name")

	var line struct {
		OutputFields map[string]any `json:"output_fields"`
	}
	require.NoError(t, json.Unmarshal([]byte(payload.Streams[0].Values[0][1]), &line))
	assert.Equal(t, "nginx-abc", line.OutputFields["k8s.pod.name"])
}

func TestBuildPayloadEmptyHostname(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Hostname = ""

	payload := buildPayload(formatJSON, nil, evt)
	_, has := payload.Streams[0].Stream["hostname"]
	assert.False(t, has)
}

func mustLabelFields(t *testing.T, fields ...string) []labelField {
	t.Helper()
	parsed, errs := parseLabelFields(fields)
	require.Empty(t, errs)
	return parsed
}

func TestBuildPayloadLabelFields(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.OutputFields["proc.aname[2]"] = "bash"
	payload := buildPayload(formatJSON, mustLabelFields(t, "fd.name", "user.name", "proc.aname[2]"), evt)

	labels := payload.Streams[0].Stream
	assert.Equal(t, "/bin/hack", labels["fd_name"])
	assert.Equal(t, "root", labels["user_name"])
	assert.Equal(t, "bash", labels["proc_aname_2"])
}

func TestBuildPayloadLabelFieldMissing(t *testing.T) {
	evt := testutil.CreateValidEvent()
	payload := buildPayload(formatJSON, mustLabelFields(t, "nonexistent"), evt)

	_, found := payload.Streams[0].Stream["nonexistent"]
	assert.False(t, found)
}

func TestParseLabelFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		want   string
		fields []string
	}{
		{name: "comma string", fields: []string{"fd.name,user.name"}, want: `label_fields[0]: "fd.name,user.name" does not make a valid label name`},
		{name: "empty", fields: []string{""}, want: `label_fields[0]: "" does not make a valid label name`},
		{name: "leading digit", fields: []string{"1st.field"}, want: `label_fields[0]: "1st.field" does not make a valid label name`},
		{name: "hyphen", fields: []string{"evt.arg.flags", "my-field"}, want: `label_fields[1]: "my-field" does not make a valid label name`},
		{name: "reserved prefix", fields: []string{"__name__"}, want: `label_fields[0]: "__name__" makes a label starting with __`},
		{name: "built-in namespace", fields: []string{"k8s.ns.name"}, want: `label_fields[0]: "k8s.ns.name" makes the built-in label k8s_ns_name`},
		{name: "built-in level", fields: []string{"level"}, want: `label_fields[0]: "level" makes the built-in label level`},
		{name: "built-in hostname", fields: []string{"hostname"}, want: `label_fields[0]: "hostname" makes the built-in label hostname`},
		{name: "same label", fields: []string{"fd.name", "fd_name"}, want: `label_fields[1]: "fd.name" and "fd_name" make the same label fd_name`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := parseLabelFields(tc.fields)
			require.NotEmpty(t, errs)
			assert.Contains(t, errs.Error(), tc.want)
		})
	}

	parsed, errs := parseLabelFields([]string{"container.name", "proc.aname[2]", "_private"})
	require.Empty(t, errs)
	assert.Equal(t, []labelField{
		{field: "container.name", label: "container_name"},
		{field: "proc.aname[2]", label: "proc_aname_2"},
		{field: "_private", label: "_private"},
	}, parsed)
}

func TestBuildBatchPayloadGroupsByLabels(t *testing.T) {
	e1 := testutil.CreateValidEvent()
	e2 := testutil.CreateValidEvent()
	e3 := testutil.CreateValidEvent()
	e3.Priority = event.PriorityCritical

	payload := buildBatchPayload(formatJSON, nil, []*event.Event{e1, e2, e3})

	assert.Len(t, payload.Streams, 2)
}

func TestBuildBatchPayloadSortsTimestamps(t *testing.T) {
	e1 := testutil.CreateValidEvent()
	e1.Time = time.Date(2026, 1, 1, 12, 0, 2, 0, time.UTC)

	e2 := testutil.CreateValidEvent()
	e2.Time = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	e3 := testutil.CreateValidEvent()
	e3.Time = time.Date(2026, 1, 1, 12, 0, 1, 0, time.UTC)

	payload := buildBatchPayload(formatJSON, nil, []*event.Event{e1, e2, e3})

	require.Len(t, payload.Streams, 1)
	values := payload.Streams[0].Values
	require.Len(t, values, 3)

	assert.True(t, values[0][0] <= values[1][0], "entries must be sorted by timestamp")
	assert.True(t, values[1][0] <= values[2][0], "entries must be sorted by timestamp")
}

func TestSortEntriesByTimestamp(t *testing.T) {
	entries := [][]string{
		{"3000", "c"},
		{"1000", "a"},
		{"2000", "b"},
	}
	sortEntriesByTimestamp(entries)
	assert.Equal(t, "1000", entries[0][0])
	assert.Equal(t, "2000", entries[1][0])
	assert.Equal(t, "3000", entries[2][0])
}
