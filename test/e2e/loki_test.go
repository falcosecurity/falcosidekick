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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lokiURLEnv = "FALCOSIDEKICK_E2E_LOKI_URL"

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// lokiQuery runs a LogQL range query over the last few minutes as tenant and
// returns the HTTP status and the streams found.
func lokiQuery(t *testing.T, base, tenant, logQL string) (int, []lokiStream) {
	t.Helper()
	query := url.Values{
		"query": {logQL},
		"start": {strconv.FormatInt(time.Now().Add(-5*time.Minute).UnixNano(), 10)},
		"end":   {strconv.FormatInt(time.Now().Add(time.Minute).UnixNano(), 10)},
		"limit": {"10"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/loki/api/v1/query_range?"+query.Encode(), http.NoBody)
	require.NoError(t, err)
	if tenant != "" {
		req.Header.Set("X-Scope-OrgID", tenant)
	}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var got struct {
		Data struct {
			Result []lokiStream `json:"result"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &got), string(body))
	return resp.StatusCode, got.Data.Result
}

// waitLokiStream polls Loki until logQL matches one stream with one entry.
func waitLokiStream(t *testing.T, base, tenant, logQL string) lokiStream {
	t.Helper()
	var streams []lokiStream
	var status int
	eventuallyf(t, func() bool {
		status, streams = lokiQuery(t, base, tenant, logQL)
		return len(streams) > 0
	}, "loki query %s: HTTP %d", logQL, &status)
	require.Len(t, streams, 1)
	require.Len(t, streams[0].Values, 1)
	return streams[0]
}

// lokiSelector matches the labels the driver sets for falcoEvent(marker)
// plus a line filter on the marker.
func lokiSelector(marker string) string {
	return fmt.Sprintf(`{rule="E2E %s", source="syscall", hostname="e2e-host"} |= %q`, marker, marker)
}

// lokiEnforcesTenants reports whether base rejects queries without a tenant,
// which is the case only when Loki runs with auth_enabled.
func lokiEnforcesTenants(t *testing.T, base string) bool {
	t.Helper()
	status, _ := lokiQuery(t, base, "", `{source="syscall"}`)
	return status == http.StatusUnauthorized
}

func TestLokiDeliversEvent(t *testing.T) {
	base := requireEnv(t, lokiURLEnv)
	const tenant = "e2e-falco"
	sk := startSidekick(t, fmt.Sprintf("loki:\n  host: %q\n  tenant: %s\n", base, tenant))

	marker := newMarker(t)
	before := time.Now()
	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "loki", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)

	stream := waitLokiStream(t, base, tenant, lokiSelector(marker))
	assert.Equal(t, "E2E "+marker, stream.Stream["rule"])
	assert.Equal(t, "warning", stream.Stream["priority"])
	assert.Equal(t, "syscall", stream.Stream["source"])
	assert.Equal(t, "e2e-host", stream.Stream["hostname"])
	assert.Equal(t, "e2e", stream.Stream["tags"])

	entry := stream.Values[0]
	ts, err := strconv.ParseInt(entry[0], 10, 64)
	require.NoError(t, err)
	assert.WithinDuration(t, before, time.Unix(0, ts), time.Minute)
	var line map[string]any
	require.NoError(t, json.Unmarshal([]byte(entry[1]), &line), entry[1])
	assert.Equal(t, "E2E "+marker, line["rule"])
	assert.Equal(t, "e2e event "+marker, line["output"])
	assert.NotEmpty(t, line["uuid"])
	fields, ok := line["output_fields"].(map[string]any)
	require.True(t, ok, entry[1])
	assert.Equal(t, marker, fields["e2e.marker"])
}

func TestLokiTextFormatWithExtraLabels(t *testing.T) {
	base := requireEnv(t, lokiURLEnv)
	const tenant = "e2e-falco"
	sk := startSidekick(t, fmt.Sprintf(`loki:
  host: %q
  endpoint: /loki/api/v1/push
  tenant: %s
  log_format: text
  extra_labels: "e2e.marker, proc.name"
`, base, tenant))

	marker := newMarker(t)
	sk.postEvent(t, marker)
	sk.waitStatus(t, "loki", func(st outputStatus) bool { return st.SentTotal == 1 })

	stream := waitLokiStream(t, base, tenant, fmt.Sprintf(`{e2e_marker=%q}`, marker))
	assert.Equal(t, "e2e", stream.Stream["proc_name"])
	assert.Equal(t, "E2E "+marker, stream.Stream["rule"])
	assert.Equal(t, "e2e event "+marker, stream.Values[0][1])
}

func TestLokiTenantIsolation(t *testing.T) {
	base := requireEnv(t, lokiURLEnv)
	if !lokiEnforcesTenants(t, base) {
		t.Skip("Loki runs without auth_enabled; X-Scope-OrgID is ignored")
	}
	sk := startSidekick(t, fmt.Sprintf("loki:\n  host: %q\n  tenant: e2e-tenant-a\n", base))

	marker := newMarker(t)
	sk.postEvent(t, marker)
	sk.waitStatus(t, "loki", func(st outputStatus) bool { return st.SentTotal == 1 })

	waitLokiStream(t, base, "e2e-tenant-a", lokiSelector(marker))
	status, streams := lokiQuery(t, base, "e2e-tenant-b", lokiSelector(marker))
	assert.Equal(t, http.StatusOK, status)
	assert.Empty(t, streams, "another tenant must not see the event")
}

func TestLokiMissingTenantIsRejected(t *testing.T) {
	base := requireEnv(t, lokiURLEnv)
	if !lokiEnforcesTenants(t, base) {
		t.Skip("Loki runs without auth_enabled; pushes without a tenant are accepted")
	}
	sk := startSidekick(t, fmt.Sprintf("loki:\n  host: %q\n", base))

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "loki", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "HTTP 401")
}

// A wrong base path makes the readiness probe answer 404, a configuration
// error that stops startup.
func TestLokiWrongBasePathFailsStartup(t *testing.T) {
	base := requireEnv(t, lokiURLEnv)
	logs := startSidekickFails(t, fmt.Sprintf("loki:\n  host: %q\n  base_path: /e2e-missing\n  tenant: e2e-falco\n", base))
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "HTTP 404")
}

// A wrong endpoint is only visible on delivery.
func TestLokiReportsWrongEndpoint(t *testing.T) {
	base := requireEnv(t, lokiURLEnv)
	sk := startSidekick(t, fmt.Sprintf("loki:\n  host: %q\n  endpoint: /e2e-missing\n  tenant: e2e-falco\n", base))
	assert.Equal(t, "idle", sk.status(t, "loki").Status)

	sk.postEvent(t, newMarker(t))
	st := sk.waitStatus(t, "loki", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Equal(t, "error", st.Status)
	assert.Contains(t, st.LastError, "HTTP 404")
}

// An unreachable destination at startup is transient: the output starts
// degraded and reports why.
func TestLokiUnreachableStartsDegraded(t *testing.T) {
	sk := startSidekick(t, fmt.Sprintf("loki:\n  host: %q\n", "http://127.0.0.1:19098"))
	st := sk.status(t, "loki")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "health check failed before start")
}
