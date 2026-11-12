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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestBuildAlertIncludesAlertname(t *testing.T) {
	o := &driver{cfg: config{}}
	evt := testutil.CreateValidEvent()
	alert := o.buildAlert(evt)

	assert.NotEmpty(t, alert.Labels["alertname"], "must set alertname for AM routing")
	assert.Equal(t, evt.Rule, alert.Labels["alertname"])
}

func TestBuildAlertKeepsRuleVerbatim(t *testing.T) {
	o := &driver{cfg: config{}}
	evt := testutil.CreateValidEvent()
	evt.Rule = "Write below binary dir (k8s.io/ns)"
	alert := o.buildAlert(evt)

	assert.Equal(t, evt.Rule, alert.Labels["alertname"], "label values are free text in Alertmanager")
}

func TestBuildAlertLabelsAndAnnotations(t *testing.T) {
	o := &driver{cfg: config{}}
	evt := testutil.CreateValidEvent()
	alert := o.buildAlert(evt)

	assert.Equal(t, map[string]string{
		"alertname": "Write below binary dir",
		"source":    "syscall",
		"priority":  "Error",
		"severity":  "warning",
		"hostname":  "node-1",
		"tags":      "filesystem,mitre_persistence",
	}, alert.Labels, "no rule label: alertname carries the rule")
	assert.Equal(t, map[string]string{
		"summary":     evt.Rule,
		"description": evt.Output,
	}, alert.Annotations, "no info annotation")
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
	assert.Equal(t, evt.Output, alert.Annotations["description"])
}

func TestBuildAlertNoExpiresAfter(t *testing.T) {
	o := &driver{cfg: config{}}
	alert := o.buildAlert(testutil.CreateValidEvent())
	assert.Empty(t, alert.EndsAt)
}

func TestBuildAlertExpiresAfter(t *testing.T) {
	o := &driver{cfg: config{ExpiresAfter: 30 * time.Minute}}
	alert := o.buildAlert(testutil.CreateValidEvent())
	assert.Equal(t, "2026-04-01T11:00:00Z", alert.EndsAt)
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
		ExtraLabels: map[string]string{"env": "production", "k8s_ns": "default", "severity": "page"},
	}}
	alert := o.buildAlert(testutil.CreateValidEvent())

	assert.Equal(t, "production", alert.Labels["env"])
	assert.Equal(t, "default", alert.Labels["k8s_ns"])
	assert.Equal(t, "page", alert.Labels["severity"], "extra labels replace built-in labels")
}

func TestBuildAlertKeepsLabelValues(t *testing.T) {
	o := &driver{cfg: config{
		ExtraLabels: map[string]string{"region": "eu-west-1", "url": "https://x.example/a b", "team_name": "sec/ops"},
	}}
	evt := testutil.CreateValidEvent()
	evt.Hostname = "node-1.eu-west-1.internal"
	evt.Tags = []string{"mitre-execution", "T1059"}
	alert := o.buildAlert(evt)

	assert.Equal(t, "eu-west-1", alert.Labels["region"])
	assert.Equal(t, "https://x.example/a b", alert.Labels["url"])
	assert.Equal(t, "sec/ops", alert.Labels["team_name"])
	assert.Equal(t, "node-1.eu-west-1.internal", alert.Labels["hostname"])
	assert.Equal(t, "T1059,mitre-execution", alert.Labels["tags"])
}

func TestResolveSeverityDefault(t *testing.T) {
	o := &driver{cfg: config{}}
	tests := map[event.Priority]string{
		event.PriorityEmergency:     "critical",
		event.PriorityAlert:         "critical",
		event.PriorityCritical:      "critical",
		event.PriorityError:         "warning",
		event.PriorityWarning:       "warning",
		event.PriorityNotice:        "info",
		event.PriorityInformational: "info",
		event.PriorityDebug:         "info",
	}
	for p, want := range tests {
		t.Run(string(p), func(t *testing.T) {
			assert.Equal(t, want, o.resolveSeverity(p))
		})
	}
}

// Keys are Falco priorities in any case Falco accepts, info included.
func TestResolveSeverityCustomMapOverride(t *testing.T) {
	d, err := createOutput(map[string]any{
		"hosts":               []string{"http://am:9093"},
		"custom_severity_map": map[string]any{"Critical": "P1", "warning": "P3", "info": "P5"},
	}, output.Deps{})
	require.NoError(t, err)
	o := d.(*driver)
	assert.Equal(t, "P1", o.resolveSeverity(event.PriorityCritical))
	assert.Equal(t, "P3", o.resolveSeverity(event.PriorityWarning))
	assert.Equal(t, "P5", o.resolveSeverity(event.PriorityInformational))
	assert.Equal(t, "info", o.resolveSeverity(event.PriorityDebug))
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		cfg     map[string]any
		name    string
		wantErr string
	}{
		{name: "duration", cfg: map[string]any{"expires_after": "30m"}},
		{name: "zero", cfg: map[string]any{"expires_after": "0"}},
		{name: "integer seconds", cfg: map[string]any{"expires_after": 300}, wantErr: "expires_after: must be a duration such as 30s or 1m"},
		{name: "integer zero", cfg: map[string]any{"expires_after": 0}},
		{name: "number without unit", cfg: map[string]any{"expires_after": "300"}, wantErr: "expires_after"},
		{name: "negative", cfg: map[string]any{"expires_after": "-1m"}, wantErr: "expires_after: must be 0 or a Go duration"},
		{name: "valid label names", cfg: map[string]any{"extra_labels": map[string]any{"_team": "a", "env2": "b"}}},
		{name: "dotted label name", cfg: map[string]any{"extra_labels": map[string]any{"k8s.ns": "a"}}, wantErr: `extra_labels["k8s.ns"]: name must match`},
		{name: "label name with digit first", cfg: map[string]any{"extra_labels": map[string]any{"1env": "a"}}, wantErr: `extra_labels["1env"]: name must match`},
		{name: "label name with dash", cfg: map[string]any{"extra_labels": map[string]any{"team-name": "a"}}, wantErr: `extra_labels["team-name"]: name must match`},
		{name: "severity map by priority", cfg: map[string]any{"custom_severity_map": map[string]any{"Emergency": "P1", "informational": "P5"}}},
		{name: "unknown severity map key", cfg: map[string]any{"custom_severity_map": map[string]any{"crit": "P1"}},
			wantErr: `custom_severity_map["crit"]: must be a Falco priority`},
		{name: "priority mapped twice", cfg: map[string]any{"custom_severity_map": map[string]any{"info": "P5", "informational": "P4"}},
			wantErr: `custom_severity_map["informational"]: names a priority already mapped`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg["hosts"] = []string{"http://am:9093"}
			_, err := createOutput(tt.cfg, output.Deps{})
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
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
