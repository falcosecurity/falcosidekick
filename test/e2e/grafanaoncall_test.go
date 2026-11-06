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
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	onCallToken       = "e2eOnCallIntegrationToken"
	onCallSecretPath  = "/integrations/v1/formatted_webhook/" + onCallToken + "/"
	onCallBearerToken = "glsa_e2eServiceAccountToken"
)

// onCallAlert mirrors the documented formatted webhook payload:
// https://grafana.com/docs/grafana-cloud/alerting-and-irm/irm/configure/integrations/webhooks/incoming-webhooks/oncall-webhooks
type onCallAlert struct {
	AlertUID              string `json:"alert_uid"`
	Title                 string `json:"title"`
	ImageURL              string `json:"image_url"`
	State                 string `json:"state"`
	LinkToUpstreamDetails string `json:"link_to_upstream_details"`
	Message               string `json:"message"`
}

// onCallIntegration is a strict fake; with bearer set it answers 403 without that token, as OnCall does.
type onCallIntegration struct {
	bearer   string
	alerts   []onCallAlert
	rejected []string
	status   int
	mu       sync.Mutex
}

func (o *onCallIntegration) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	reject := func(status int, reason string) {
		o.rejected = append(o.rejected, req.Method+" "+req.URL.Path+": "+reason)
		w.WriteHeader(status)
	}
	if req.URL.Path != onCallSecretPath {
		reject(http.StatusNotFound, "unknown integration")
		return
	}
	if req.Method != http.MethodPost {
		reject(http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if o.bearer != "" && req.Header.Get("Authorization") != "Bearer "+o.bearer {
		o.rejected = append(o.rejected, "missing or invalid bearer token")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusUnsupportedMediaType, "content type "+req.Header.Get("Content-Type"))
		return
	}
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	var alert onCallAlert
	if err := dec.Decode(&alert); err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	if dec.More() {
		reject(http.StatusBadRequest, "trailing data")
		return
	}
	if alert.State != "alerting" && alert.State != "ok" {
		reject(http.StatusBadRequest, "state "+alert.State)
		return
	}
	o.alerts = append(o.alerts, alert)
	w.WriteHeader(o.status)
	_, _ = io.WriteString(w, "{}")
}

func (o *onCallIntegration) snapshot() (alerts []onCallAlert, rejected []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]onCallAlert(nil), o.alerts...), append([]string(nil), o.rejected...)
}

func startOnCall(t *testing.T, integration *onCallIntegration, extra string) *sidekick {
	t.Helper()
	server := httptest.NewServer(integration)
	t.Cleanup(server.Close)
	return startSidekick(t, fmt.Sprintf("grafanaoncall:\n  host: %q\n  secret_endpoint: %q\n%s", server.URL, onCallSecretPath, extra))
}

func TestGrafanaOnCallDeliversEvent(t *testing.T) {
	integration := &onCallIntegration{status: http.StatusOK, bearer: onCallBearerToken}
	sk := startOnCall(t, integration, fmt.Sprintf("  bearer_token: %q\n", onCallBearerToken))
	assert.Equal(t, "idle", sk.status(t, "grafanaoncall").Status)

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "grafanaoncall", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	alerts, rejected := integration.snapshot()
	require.Empty(t, rejected)
	require.Len(t, alerts, 1)
	alert := alerts[0]
	assert.NotEmpty(t, alert.AlertUID)
	assert.Equal(t, "alerting", alert.State)
	assert.Equal(t, "[Warning] E2E "+marker, alert.Title)
	assert.Equal(t, "e2e event "+marker, alert.Message)
	assert.NotContains(t, sk.logs.String(), onCallToken)
	assert.NotContains(t, sk.logs.String(), onCallBearerToken)
}

// A 403 for a wrong token is reported without leaking the integration URL or the token.
func TestGrafanaOnCallReportsRejectedToken(t *testing.T) {
	integration := &onCallIntegration{status: http.StatusOK, bearer: onCallBearerToken}
	sk := startOnCall(t, integration, "  bearer_token: glsa_wrongE2EToken\n")

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "grafanaoncall", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 403")
	for _, secret := range []string{onCallToken, "glsa_wrongE2EToken"} {
		assert.NotContains(t, st.LastError, secret)
		assert.NotContains(t, sk.logs.String(), secret)
	}
	alerts, rejected := integration.snapshot()
	assert.Empty(t, alerts)
	assert.Len(t, rejected, 1, "max_attempts 1 sends exactly once")
}

func TestGrafanaOnCallReportsUnknownIntegration(t *testing.T) {
	integration := &onCallIntegration{status: http.StatusOK}
	server := httptest.NewServer(integration)
	t.Cleanup(server.Close)
	revoked := "/integrations/v1/formatted_webhook/" + onCallToken + "-revoked/"
	sk := startSidekick(t, fmt.Sprintf("grafanaoncall:\n  host: %q\n  secret_endpoint: %q\n", server.URL, revoked))

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "grafanaoncall", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Contains(t, st.LastError, "HTTP 404")
	assert.NotContains(t, st.LastError, onCallToken)
	assert.NotContains(t, sk.logs.String(), onCallToken)
}

// Probing the integration would create an alert, so an unreachable host fails only on delivery.
func TestGrafanaOnCallUnreachableAtStartup(t *testing.T) {
	sk := startSidekick(t, fmt.Sprintf("grafanaoncall:\n  host: \"http://127.0.0.1:1\"\n  secret_endpoint: %q\n", onCallSecretPath))
	assert.Equal(t, "idle", sk.status(t, "grafanaoncall").Status, "no probe, so not degraded")

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "grafanaoncall", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.NotEmpty(t, st.LastError)
	assert.NotContains(t, st.LastError, onCallToken)
	assert.NotContains(t, sk.logs.String(), onCallToken)
}

func TestGrafanaOnCallSecretAbsentFromAPI(t *testing.T) {
	integration := &onCallIntegration{status: http.StatusOK}
	sk := startOnCall(t, integration, fmt.Sprintf("  bearer_token: %q\n", onCallBearerToken))
	for _, path := range []string{
		"/api/v1/config", "/api/v1/pipeline/outputs/grafanaoncall", "/api/v1/pipeline/status/grafanaoncall",
	} {
		resp, err := httpDo(http.MethodGet, sk.apiURL+path, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		assert.NotContains(t, string(body), onCallToken, path)
		assert.NotContains(t, string(body), onCallBearerToken, path)
	}
}
