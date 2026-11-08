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

func TestBuildPayloadLabels(t *testing.T) {
	evt := testutil.CreateValidEvent()
	payload := buildPayload(formatJSON, nil, evt)

	require.Len(t, payload.Streams, 1)
	labels := payload.Streams[0].Stream
	assert.Equal(t, evt.Rule, labels["rule"])
	assert.Equal(t, evt.Source, labels["source"])
	assert.Equal(t, string(evt.Priority), labels["priority"])
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

func TestBuildPayloadTags(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Tags = []string{"z_tag", "a_tag"}

	payload := buildPayload(formatJSON, nil, evt)
	assert.Equal(t, "a_tag,z_tag", payload.Streams[0].Stream["tags"])
}

func TestBuildPayloadNoTags(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Tags = nil

	payload := buildPayload(formatJSON, nil, evt)
	_, has := payload.Streams[0].Stream["tags"]
	assert.False(t, has)
}

func TestBuildPayloadK8sFields(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.OutputFields["k8s.ns.name"] = "default"
	evt.OutputFields["k8s.pod.name"] = "nginx-abc"

	payload := buildPayload(formatJSON, nil, evt)
	labels := payload.Streams[0].Stream
	assert.Equal(t, "default", labels["k8s_ns_name"])
	assert.Equal(t, "nginx-abc", labels["k8s_pod_name"])
}

func TestBuildPayloadEmptyHostname(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Hostname = ""

	payload := buildPayload(formatJSON, nil, evt)
	_, has := payload.Streams[0].Stream["hostname"]
	assert.False(t, has)
}

func TestBuildPayloadExtraLabels(t *testing.T) {
	evt := testutil.CreateValidEvent()
	payload := buildPayload(formatJSON, []string{"fd.name", "user.name"}, evt)

	labels := payload.Streams[0].Stream
	assert.Equal(t, "/bin/hack", labels["fd_name"])
	assert.Equal(t, "root", labels["user_name"])
}

func TestBuildPayloadExtraLabelMissing(t *testing.T) {
	evt := testutil.CreateValidEvent()
	payload := buildPayload(formatJSON, []string{"nonexistent"}, evt)

	_, found := payload.Streams[0].Stream["nonexistent"]
	assert.False(t, found)
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
