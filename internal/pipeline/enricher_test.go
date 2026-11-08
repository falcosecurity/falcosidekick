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

package pipeline

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func newTestEvent() *event.Event {
	return &event.Event{
		Time:         time.Now(),
		Rule:         "Test rule",
		Priority:     event.PriorityWarning,
		Output:       "test output",
		Source:       "syscall",
		OutputFields: map[string]interface{}{"proc.name": "bash"},
		Tags:         []string{"tag1"},
		Hostname:     "node-1",
	}
}

func testEnricherConfig() output.EnricherConfig {
	return output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	}
}

func TestNewEnricherWithValidConfig(t *testing.T) {
	e, err := NewEnricher(testEnricherConfig())
	require.NoError(t, err)
	require.NotNil(t, e)
}

func TestNewEnricherInvalidTemplate(t *testing.T) {
	_, err := NewEnricher(output.EnricherConfig{
		TemplatedFields: map[string]string{"bad": "{{ .Invalid | "},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse template")
}

func TestEnricherConfigValidateValid(t *testing.T) {
	cfg := testEnricherConfig()
	assert.Empty(t, cfg.Validate())
}

func TestEnricherConfigValidateNegativeEventThreshold(t *testing.T) {
	cfg := output.EnricherConfig{TruncateEventThreshold: -1}
	assert.NotEmpty(t, cfg.Validate())
}

func TestEnricherConfigValidateTooSmallFieldThreshold(t *testing.T) {
	cfg := output.EnricherConfig{TruncateEventThreshold: 100, TruncateFieldThreshold: 3}
	assert.NotEmpty(t, cfg.Validate())
}

func TestEnricherConfigValidateDisabledTruncation(t *testing.T) {
	cfg := output.EnricherConfig{TruncateEventThreshold: 0, TruncateFieldThreshold: 0}
	assert.Empty(t, cfg.Validate())
}

func TestEnricherConfigValidateZeroThresholds(t *testing.T) {
	cfg := output.EnricherConfig{}
	assert.Empty(t, cfg.Validate())
}

func TestEnrichGeneratesUUID(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	evt := newTestEvent()

	require.NoError(t, e.Enrich(evt))
	assert.NotEmpty(t, evt.UUID)
	assert.Len(t, evt.UUID, 36)
}

func TestEnrichUUIDUniqueness(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	e1 := newTestEvent()
	e2 := newTestEvent()

	require.NoError(t, e.Enrich(e1))
	require.NoError(t, e.Enrich(e2))
	assert.NotEqual(t, e1.UUID, e2.UUID)
}

func TestEnrichInjectsCustomFields(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.CustomFields = map[string]string{"env": "prod", "cluster": "us-1"}
	e, _ := NewEnricher(cfg)
	evt := newTestEvent()

	require.NoError(t, e.Enrich(evt))
	assert.Equal(t, "prod", evt.OutputFields["env"])
	assert.Equal(t, "us-1", evt.OutputFields["cluster"])
	assert.Equal(t, "bash", evt.OutputFields["proc.name"])
}

func TestEnrichEvaluatesTemplatedFields(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.TemplatedFields = map[string]string{
		"proc_info": `process={{ index . "proc.name" }}`,
	}
	e, _ := NewEnricher(cfg)
	evt := newTestEvent()

	require.NoError(t, e.Enrich(evt))
	assert.Equal(t, "process=bash", evt.OutputFields["proc_info"])
}

func TestEnrichTemplateErrorContinues(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.TemplatedFields = map[string]string{
		"bad": `{{ call . }}`,
	}
	e, _ := NewEnricher(cfg)
	evt := newTestEvent()

	require.NoError(t, e.Enrich(evt))
	_, exists := evt.OutputFields["bad"]
	assert.False(t, exists)
}

func TestEnrichInjectsCustomTags(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.CustomTags = []string{"security", "falco"}
	e, _ := NewEnricher(cfg)
	evt := newTestEvent()

	require.NoError(t, e.Enrich(evt))
	assert.Equal(t, []string{"falco", "security", "tag1"}, evt.Tags)
}

func TestEnrichNoCustomTagsPreservesOriginal(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	evt := newTestEvent()
	original := make([]string, len(evt.Tags))
	copy(original, evt.Tags)

	require.NoError(t, e.Enrich(evt))
	assert.Equal(t, original, evt.Tags)
}

func TestEnrichDefaultHostname(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	evt := newTestEvent()
	evt.Hostname = ""

	require.NoError(t, e.Enrich(evt))
	assert.Equal(t, defaultHostname, evt.Hostname)
}

func TestEnrichPreservesExistingHostname(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	evt := newTestEvent()

	require.NoError(t, e.Enrich(evt))
	assert.Equal(t, "node-1", evt.Hostname)
}

func TestEnrichReplacesBrackets(t *testing.T) {
	cfg := testEnricherConfig()
	cfg.BracketReplacer = "_"
	e, _ := NewEnricher(cfg)
	evt := newTestEvent()
	const testPath = "/dev/null"
	evt.OutputFields["fd[0]"] = testPath

	require.NoError(t, e.Enrich(evt))
	assert.Equal(t, testPath, evt.OutputFields["fd_0_"])
	_, hasBrackets := evt.OutputFields["fd[0]"]
	assert.False(t, hasBrackets)
}

func TestEnrichNoBracketReplacerSkips(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	evt := newTestEvent()
	const testPath = "/dev/null"
	evt.OutputFields["fd[0]"] = testPath

	require.NoError(t, e.Enrich(evt))
	assert.Equal(t, testPath, evt.OutputFields["fd[0]"])
}

func TestEnrichTruncatesLargeEvents(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	evt := newTestEvent()
	for i := 0; i < 10; i++ {
		evt.OutputFields[strings.Repeat("field", i+1)] = strings.Repeat("x", 1000)
	}

	require.NoError(t, e.Enrich(evt))

	truncated := false
	for _, v := range evt.OutputFields {
		s, ok := v.(string)
		if ok && strings.HasSuffix(s, truncateFieldSuffix) {
			truncated = true
			assert.LessOrEqual(t, len(s), testEnricherConfig().TruncateFieldThreshold)
		}
	}
	assert.True(t, truncated, "at least one field should be truncated")
}

func TestEnrichCustomTruncateThresholds(t *testing.T) {
	e, _ := NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 200,
		TruncateFieldThreshold: 50,
	})
	evt := newTestEvent()
	evt.OutputFields["data"] = strings.Repeat("a", 100)

	require.NoError(t, e.Enrich(evt))

	val := evt.OutputFields["data"].(string)
	assert.LessOrEqual(t, len(val), 50)
	assert.True(t, strings.HasSuffix(val, truncateFieldSuffix))
}

func TestEnrichTruncateThresholdsFromConfig(t *testing.T) {
	cfg := testEnricherConfig()
	e, _ := NewEnricher(cfg)
	assert.Equal(t, cfg.TruncateEventThreshold, e.cfg.TruncateEventThreshold)
	assert.Equal(t, cfg.TruncateFieldThreshold, e.cfg.TruncateFieldThreshold)
}

func TestEnrichDoesNotTruncateSmallEvents(t *testing.T) {
	e, _ := NewEnricher(testEnricherConfig())
	evt := newTestEvent()
	evt.OutputFields["small"] = "tiny"

	require.NoError(t, e.Enrich(evt))
	assert.Equal(t, "tiny", evt.OutputFields["small"])
}
