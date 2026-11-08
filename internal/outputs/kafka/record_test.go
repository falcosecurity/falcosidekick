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

package kafka

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestResolveTopicDefault(t *testing.T) {
	o := &driver{cfg: config{Topic: "default-topic"}}
	event := testutil.CreateValidEvent()

	assert.Equal(t, "default-topic", o.resolveTopic(event))
}

func TestResolveTopicFromField(t *testing.T) {
	o := &driver{cfg: config{Topic: "default", TopicField: "k8s.ns.name"}}
	event := testutil.CreateValidEvent()
	event.OutputFields["k8s.ns.name"] = "production"

	assert.Equal(t, "production", o.resolveTopic(event))
}

func TestResolveTopicFieldMissingFallsBack(t *testing.T) {
	o := &driver{cfg: config{Topic: "default", TopicField: "nonexistent"}}
	event := testutil.CreateValidEvent()

	assert.Equal(t, "default", o.resolveTopic(event))
}

func TestResolveTopicFieldNonStringFallsBack(t *testing.T) {
	o := &driver{cfg: config{Topic: "default", TopicField: "count"}}
	event := testutil.CreateValidEvent()
	event.OutputFields["count"] = 42

	assert.Equal(t, "default", o.resolveTopic(event))
}

func TestResolveKeyStatic(t *testing.T) {
	o := &driver{cfg: config{MessageKey: "static-key"}}
	event := testutil.CreateValidEvent()

	assert.Equal(t, []byte("static-key"), o.resolveKey(event))
}

func TestResolveKeyFromField(t *testing.T) {
	o := &driver{cfg: config{MessageKeyField: "hostname"}}
	event := testutil.CreateValidEvent()
	event.OutputFields["hostname"] = testutil.CreateValidEvent().Hostname

	assert.Equal(t, []byte("node-1"), o.resolveKey(event))
}

func TestResolveKeyFieldOverridesStatic(t *testing.T) {
	o := &driver{cfg: config{MessageKey: "static", MessageKeyField: "hostname"}}
	event := testutil.CreateValidEvent()
	event.OutputFields["hostname"] = testutil.CreateValidEvent().Hostname

	assert.Equal(t, []byte("node-1"), o.resolveKey(event), "field key takes priority over static")
}

func TestResolveKeyNilWhenUnconfigured(t *testing.T) {
	o := &driver{cfg: config{}}
	event := testutil.CreateValidEvent()

	assert.Nil(t, o.resolveKey(event))
}

func TestBuildHeadersIncludesExpectedKeys(t *testing.T) {
	event := testutil.CreateValidEvent()
	headers := buildHeaders(event)

	require.Len(t, headers, 4)
	keys := make([]string, len(headers))
	for i, h := range headers {
		keys[i] = h.Key
	}
	assert.Contains(t, keys, "content-type")
	assert.Contains(t, keys, "falco.rule")
	assert.Contains(t, keys, "falco.priority")
	assert.Contains(t, keys, "falco.source")
}

func TestBuildRecordCombinesAllFields(t *testing.T) {
	o := &driver{cfg: config{
		Topic:           "events",
		MessageKey:      "my-key",
		MessageKeyField: "",
	}}
	event := testutil.CreateValidEvent()

	record, err := o.buildRecord(event)
	require.NoError(t, err)
	assert.Equal(t, "events", record.Topic)
	assert.Equal(t, []byte("my-key"), record.Key)
	assert.NotEmpty(t, record.Value)
	assert.NotEmpty(t, record.Headers)
}
