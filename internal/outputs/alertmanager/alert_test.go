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

package alertmanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestBuildAlertIncludesAlertname(t *testing.T) {
	o := &driver{cfg: config{}}
	evt := testutil.CreateValidEvent()
	alert := o.buildAlert(evt)

	assert.NotEmpty(t, alert.Labels["alertname"], "must set alertname for AM routing")
	assert.Equal(t, shared.SanitizeLabel(evt.Rule), alert.Labels["alertname"])
}

func TestBuildAlertIncludesStartsAt(t *testing.T) {
	o := &driver{cfg: config{}}
	evt := testutil.CreateValidEvent()
	alert := o.buildAlert(evt)

	assert.NotEmpty(t, alert.StartsAt, "must set startsAt for dedup/timing")
	assert.Contains(t, alert.StartsAt, "T", "startsAt must be RFC3339")
}

func TestBuildAlertIncludesGeneratorURL(t *testing.T) {
	o := &driver{cfg: config{GeneratorURL: "http://sidekick:2801"}}
	evt := testutil.CreateValidEvent()
	alert := o.buildAlert(evt)

	assert.Equal(t, "http://sidekick:2801", alert.GeneratorURL)
}

func TestBuildAlertNoGeneratorURLWhenEmpty(t *testing.T) {
	o := &driver{cfg: config{}}
	evt := testutil.CreateValidEvent()
	alert := o.buildAlert(evt)

	assert.Empty(t, alert.GeneratorURL)
}

func TestBuildAlertNoHostnameWhenEmpty(t *testing.T) {
	o := &driver{cfg: config{}}
	evt := testutil.CreateValidEvent()
	evt.Hostname = ""
	alert := o.buildAlert(evt)

	_, has := alert.Labels["hostname"]
	assert.False(t, has, "empty hostname must not produce a label")
}

func TestBuildAlertExtraAnnotations(t *testing.T) {
	o := &driver{cfg: config{
		ExtraAnnotations: map[string]string{
			"runbook": "https://example.com/runbook",
			"team":    "security",
		},
	}}
	evt := testutil.CreateValidEvent()
	alert := o.buildAlert(evt)

	assert.Equal(t, "https://example.com/runbook", alert.Annotations["runbook"])
	assert.Equal(t, "security", alert.Annotations["team"])
	assert.NotEmpty(t, alert.Annotations["info"])
}

func TestBuildAlertNoExpiresAfter(t *testing.T) {
	o := &driver{cfg: config{}}
	alert := o.buildAlert(testutil.CreateValidEvent())
	assert.Empty(t, alert.EndsAt)
}

func TestBuildAlertExpiresAfter(t *testing.T) {
	o := &driver{cfg: config{ExpiresAfter: 300}}
	alert := o.buildAlert(testutil.CreateValidEvent())
	assert.NotEmpty(t, alert.EndsAt)
}

func TestBuildAlertTagsSorted(t *testing.T) {
	o := &driver{cfg: config{}}
	evt := testutil.CreateValidEvent()
	evt.Tags = []string{"z_tag", "a_tag", "m_tag"}
	alert := o.buildAlert(evt)

	assert.Equal(t, "a_tag,m_tag,z_tag", alert.Labels["tags"])
}

func TestBuildAlertNoTags(t *testing.T) {
	o := &driver{cfg: config{}}
	evt := testutil.CreateValidEvent()
	evt.Tags = nil
	alert := o.buildAlert(evt)

	_, has := alert.Labels["tags"]
	assert.False(t, has)
}

func TestBuildAlertExtraLabels(t *testing.T) {
	o := &driver{cfg: config{
		ExtraLabels: map[string]string{"env": "production", "k8s.ns": "default"},
	}}
	alert := o.buildAlert(testutil.CreateValidEvent())

	assert.Equal(t, "production", alert.Labels["env"])
	assert.Equal(t, "default", alert.Labels["k8s_ns"])
}

func TestResolveSeverityUsesSharedDefault(t *testing.T) {
	o := &driver{cfg: config{}}
	priorities := []event.Priority{
		event.PriorityDebug, event.PriorityInformational, event.PriorityNotice,
		event.PriorityWarning, event.PriorityError, event.PriorityCritical,
		event.PriorityAlert, event.PriorityEmergency,
	}
	for _, p := range priorities {
		t.Run(string(p), func(t *testing.T) {
			assert.Equal(t, shared.PrioritySeverity(p), o.resolveSeverity(p))
		})
	}
}

func TestResolveSeverityCustomMapOverride(t *testing.T) {
	o := &driver{cfg: config{
		CustomSeverityMap: map[string]string{"critical": "P1", "warning": "P3"},
	}}
	assert.Equal(t, "P1", o.resolveSeverity(event.PriorityCritical))
	assert.Equal(t, "P3", o.resolveSeverity(event.PriorityWarning))
	assert.Equal(t, shared.PrioritySeverity(event.PriorityDebug), o.resolveSeverity(event.PriorityDebug))
}

func TestAlertmanagerMultiHost(t *testing.T) {
	d, err := createOutput(map[string]any{
		"hosts": []string{"http://am1:9093", "http://am2:9093"},
	}, output.Deps{})
	require.NoError(t, err)

	o := d.(*driver)
	assert.Len(t, o.cfg.Hosts, 2)
	assert.NotNil(t, o.sender)
}
