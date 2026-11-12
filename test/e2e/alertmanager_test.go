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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Local origins with no listener.
const (
	alertmanagerUnreachable  = "http://127.0.0.1:19094"
	alertmanagerUnreachable2 = "http://127.0.0.1:19097"
)

type alertmanagerAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
}

// alertmanagerRule is the alertname label of the marker event; label values arrive verbatim.
func alertmanagerRule(marker string) string {
	return "E2E " + marker
}

func alertmanagerAlerts(t *testing.T, baseURL, marker string) []alertmanagerAlert {
	t.Helper()
	query := url.Values{"filter": {fmt.Sprintf("alertname=%q", alertmanagerRule(marker))}}
	resp, err := httpDo(http.MethodGet, baseURL+"/api/v2/alerts?"+query.Encode(), nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var alerts []alertmanagerAlert
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&alerts))
	return alerts
}

func waitAlertmanagerAlert(t *testing.T, baseURL, marker string) alertmanagerAlert {
	t.Helper()
	var alerts []alertmanagerAlert
	eventuallyf(t, func() bool {
		alerts = alertmanagerAlerts(t, baseURL, marker)
		return len(alerts) > 0
	}, "alert with rule %s", alertmanagerRule(marker))
	require.Len(t, alerts, 1)
	return alerts[0]
}

func TestAlertmanagerDeliversAlert(t *testing.T) {
	amURL := requireEnv(t, "FALCOSIDEKICK_E2E_ALERTMANAGER_URL")
	sk := startSidekick(t, fmt.Sprintf(`alertmanager:
  hosts:
    - %q
  expires_after: 10m
  extra_labels:
    e2e_suite: alertmanager
    region: eu-west-1
  extra_annotations:
    runbook: https://example.com/runbook
`, amURL))

	marker := newMarker(t)
	before := time.Now()
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "alertmanager", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)
	assert.Empty(t, st.LastError)

	alert := waitAlertmanagerAlert(t, amURL, marker)
	assert.Equal(t, map[string]string{
		"alertname": alertmanagerRule(marker),
		"source":    "syscall",
		"priority":  "Warning",
		"severity":  "warning",
		"hostname":  "e2e-host",
		"tags":      "e2e",
		"e2e_suite": "alertmanager",
		"region":    "eu-west-1",
	}, alert.Labels, "label values arrive unchanged")
	assert.Equal(t, map[string]string{
		"summary":     "E2E " + marker,
		"description": "e2e event " + marker,
		"runbook":     "https://example.com/runbook",
	}, alert.Annotations)

	// startsAt and endsAt both derive from the event time at second precision.
	assert.WithinDuration(t, before, alert.StartsAt, 5*time.Second)
	assert.Equal(t, 600*time.Second, alert.EndsAt.Sub(alert.StartsAt))
}

// One accepting host counts the event as sent; a failed host only degrades the output.
func TestAlertmanagerFanOutToleratesUnreachableHost(t *testing.T) {
	amURL := requireEnv(t, "FALCOSIDEKICK_E2E_ALERTMANAGER_URL")
	sk := startSidekick(t, fmt.Sprintf(`alertmanager:
  hosts:
    - %q
    - %q
`, alertmanagerUnreachable, amURL))

	st := sk.status(t, "alertmanager")
	assert.Equal(t, "degraded", st.Status, "an unreachable host at startup degrades the output")
	assert.Contains(t, st.LastWarning, "health check failed before start")

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st = sk.waitStatus(t, "alertmanager", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)
	assert.Empty(t, st.LastError, "a partial fan-out failure is not reported as an output error")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "1 of 2 hosts failed")

	alert := waitAlertmanagerAlert(t, amURL, marker)
	assert.Equal(t, alertmanagerRule(marker), alert.Labels["alertname"])
}

func TestAlertmanagerFanOutFailsWhenAllHostsFail(t *testing.T) {
	sk := startSidekick(t, fmt.Sprintf(`alertmanager:
  hosts:
    - %q
    - %q
`, alertmanagerUnreachable, alertmanagerUnreachable2))

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "alertmanager", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Equal(t, "error", st.Status)
	assert.Contains(t, st.LastError, "all 2 hosts failed")
}

// A wrong base path fails the probe at startup; a wrong endpoint fails only on delivery.
func TestAlertmanagerReportsWrongRoute(t *testing.T) {
	amURL := requireEnv(t, "FALCOSIDEKICK_E2E_ALERTMANAGER_URL")
	t.Run("base_path", func(t *testing.T) {
		_, logs := startSidekickDegraded(t, "alertmanager", fmt.Sprintf("alertmanager:\n  hosts:\n    - %q\n  base_path: /missing\n", amURL))
		assert.Contains(t, logs, "health check")
		assert.Contains(t, logs, "HTTP 404")
	})
	t.Run("endpoint", func(t *testing.T) {
		sk := startSidekick(t, fmt.Sprintf("alertmanager:\n  hosts:\n    - %q\n  endpoint: /api/v2/missing\n", amURL))

		marker := newMarker(t)
		sk.postEvent(t, marker)
		st := sk.waitStatus(t, "alertmanager", func(st outputStatus) bool { return st.FailedTotal == 1 })
		assert.Zero(t, st.SentTotal)
		assert.Contains(t, st.LastError, "HTTP 404")
		assert.Empty(t, alertmanagerAlerts(t, amURL, marker))
	})
}
