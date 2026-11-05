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

const opsgenieAPIKey = "e2e0psg3n1eKeyS3cret"

// opsgenieAlert mirrors the documented Create Alert body:
// https://docs.opsgenie.com/docs/alert-api#create-alert
type opsgenieAlert struct {
	Details     map[string]string `json:"details"`
	Message     string            `json:"message"`
	Alias       string            `json:"alias"`
	Description string            `json:"description"`
	Entity      string            `json:"entity"`
	Source      string            `json:"source"`
	Priority    string            `json:"priority"`
	User        string            `json:"user"`
	Note        string            `json:"note"`
	Responders  json.RawMessage   `json:"responders"`
	VisibleTo   json.RawMessage   `json:"visibleTo"`
	Actions     []string          `json:"actions"`
	Tags        []string          `json:"tags"`
}

var opsgeniePriorities = map[string]bool{"P1": true, "P2": true, "P3": true, "P4": true, "P5": true}

// opsgenieAPI is a strict fake of the Alert API create endpoint and the
// heartbeat list used as the startup probe. healthStatus answers the probe;
// alertStatus answers valid alerts. Requests Opsgenie would reject are
// recorded with their reason.
type opsgenieAPI struct {
	alerts       []opsgenieAlert
	rejected     []string
	probes       int
	healthStatus int
	alertStatus  int
	mu           sync.Mutex
}

func (o *opsgenieAPI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	reject := func(status int, reason string) {
		o.rejected = append(o.rejected, req.Method+" "+req.URL.Path+": "+reason)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"message":"rejected","took":0.001,"requestId":"e2e"}`)
	}
	if req.Header.Get("Authorization") != "GenieKey "+opsgenieAPIKey {
		reject(http.StatusUnauthorized, "authorization header")
		return
	}
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/v2/heartbeats":
		o.probes++
		w.WriteHeader(o.healthStatus)
		_, _ = io.WriteString(w, `{"data":{"heartbeats":[]},"took":0.001,"requestId":"e2e"}`)
		return
	case req.Method == http.MethodPost && req.URL.Path == "/v2/alerts":
	default:
		reject(http.StatusNotFound, "unknown route")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mediaType != contentTypeJSON {
		reject(http.StatusUnsupportedMediaType, "content type "+req.Header.Get("Content-Type"))
		return
	}
	dec := json.NewDecoder(req.Body)
	dec.DisallowUnknownFields()
	var a opsgenieAlert
	if err := dec.Decode(&a); err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	switch {
	case a.Message == "" || len([]rune(a.Message)) > 130:
		reject(http.StatusUnprocessableEntity, "message length")
		return
	case len(a.Alias) > 512 || len([]rune(a.Description)) > 15000 || len(a.Entity) > 512:
		reject(http.StatusUnprocessableEntity, "field length")
		return
	case len(a.Tags) > 20:
		reject(http.StatusUnprocessableEntity, "too many tags")
		return
	case a.Priority != "" && !opsgeniePriorities[a.Priority]:
		reject(http.StatusUnprocessableEntity, "priority "+a.Priority)
		return
	}
	o.alerts = append(o.alerts, a)
	w.WriteHeader(o.alertStatus)
	_, _ = io.WriteString(w, `{"result":"Request will be processed","took":0.002,"requestId":"e2e"}`)
}

func (o *opsgenieAPI) snapshot() (alerts []opsgenieAlert, rejected []string, probes int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]opsgenieAlert(nil), o.alerts...), append([]string(nil), o.rejected...), o.probes
}

func opsgenieOutput(host, key string) string {
	return fmt.Sprintf("opsgenie:\n  host: %q\n  region: eu\n  api_key: %q\n", host, key)
}

func startOpsgenie(t *testing.T, healthStatus, alertStatus int) (*opsgenieAPI, *sidekick) {
	t.Helper()
	fake := &opsgenieAPI{healthStatus: healthStatus, alertStatus: alertStatus}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return fake, startSidekick(t, opsgenieOutput(server.URL, opsgenieAPIKey))
}

func TestOpsgenieDeliversAlert(t *testing.T) {
	fake, sk := startOpsgenie(t, http.StatusOK, http.StatusAccepted)

	marker := newMarker(t)
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "opsgenie", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	alerts, rejected, probes := fake.snapshot()
	require.Empty(t, rejected)
	assert.Equal(t, 1, probes, "startup probes the key once")
	require.Len(t, alerts, 1)
	a := alerts[0]
	assert.Equal(t, "e2e event "+marker, a.Message)
	assert.Equal(t, "E2E "+marker, a.Description)
	assert.Equal(t, "Falcosidekick", a.Entity)
	assert.Equal(t, "P4", a.Priority)
	assert.NotEmpty(t, a.Alias)
	assert.Equal(t, []string{"e2e"}, a.Tags)
	assert.Equal(t, marker, a.Details["e2e_marker"])
	assert.Equal(t, "e2e-host", a.Details["hostname"])
	assert.NotContains(t, sk.logs.String(), opsgenieAPIKey)
	for _, path := range []string{"/api/v1/pipeline/outputs/opsgenie", "/api/v1/config"} {
		assert.NotContains(t, opsgenieAPIBody(t, sk, path), opsgenieAPIKey, path)
	}
}

// A key without configuration access gets 403 on the probe but may still
// create alerts, so startup continues degraded.
func TestOpsgenieRestrictedKeyStartsDegraded(t *testing.T) {
	fake, sk := startOpsgenie(t, http.StatusForbidden, http.StatusAccepted)
	st := sk.status(t, "opsgenie")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "HTTP 403")

	sk.postEvent(t, newMarker(t))
	sk.waitStatus(t, "opsgenie", func(st outputStatus) bool { return st.SentTotal == 1 })
	alerts, rejected, _ := fake.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, alerts, 1)
}

func TestOpsgenieReportsRejectedAlert(t *testing.T) {
	fake, sk := startOpsgenie(t, http.StatusOK, http.StatusUnprocessableEntity)

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "opsgenie", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 422")
	assert.NotContains(t, st.LastError, opsgenieAPIKey)
	assert.NotContains(t, sk.logs.String(), opsgenieAPIKey)

	alerts, rejected, _ := fake.snapshot()
	assert.Empty(t, rejected)
	assert.Len(t, alerts, 1, "max_attempts 1 sends exactly once")
}

// A rejected key is a configuration error that stops startup.
func TestOpsgenieRejectedKeyFailsStartup(t *testing.T) {
	fake := &opsgenieAPI{healthStatus: http.StatusOK, alertStatus: http.StatusAccepted}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	wrong := "wrong-" + newMarker(t)
	logs := startSidekickFails(t, opsgenieOutput(server.URL, wrong))
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "HTTP 401")
	assert.NotContains(t, logs, wrong)
}

func TestOpsgenieUnreachableStartsDegraded(t *testing.T) {
	sk := startSidekick(t, opsgenieOutput(fmt.Sprintf("http://127.0.0.1:%d", freePort(t)), opsgenieAPIKey))
	st := sk.status(t, "opsgenie")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "health check failed before start")
	assert.NotContains(t, sk.logs.String(), opsgenieAPIKey)
}

func opsgenieAPIBody(t *testing.T, sk *sidekick, path string) string {
	t.Helper()
	resp, err := httpDo(http.MethodGet, sk.url+path, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, path)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}
