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

func lokiSelector(marker string) string {
	return fmt.Sprintf(`{source="syscall", hostname="e2e-host", level="warning"} |= %q`, marker)
}

// lokiEnforcesTenants is true only when Loki runs with auth_enabled.
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
	assert.Equal(t, "Warning", stream.Stream["priority"])
	assert.Equal(t, "warning", stream.Stream["level"])
	assert.Equal(t, "syscall", stream.Stream["source"])
	assert.Equal(t, "e2e-host", stream.Stream["hostname"])
	assert.NotContains(t, stream.Stream, "rule", "the rule stays in the log line")
	assert.NotContains(t, stream.Stream, "tags", "the tags stay in the log line")

	entry := stream.Values[0]
	ts, err := strconv.ParseInt(entry[0], 10, 64)
	require.NoError(t, err)
	assert.WithinDuration(t, before, time.Unix(0, ts), time.Minute)
	var line map[string]any
	require.NoError(t, json.Unmarshal([]byte(entry[1]), &line), entry[1])
	assert.Equal(t, "E2E "+marker, line["rule"])
	assert.Equal(t, []any{"e2e"}, line["tags"])
	assert.Equal(t, "e2e event "+marker, line["output"])
	assert.NotEmpty(t, line["uuid"])
	fields, ok := line["output_fields"].(map[string]any)
	require.True(t, ok, entry[1])
	assert.Equal(t, marker, fields["e2e.marker"])
}

func TestLokiTextFormatWithLabelFields(t *testing.T) {
	base := requireEnv(t, lokiURLEnv)
	const tenant = "e2e-falco"
	sk := startSidekick(t, fmt.Sprintf(`loki:
  host: %q
  endpoint: /loki/api/v1/push
  tenant: %s
  log_format: text
  label_fields: [e2e.marker, proc.name]
`, base, tenant))

	marker := newMarker(t)
	sk.postEvent(t, marker)
	sk.waitStatus(t, "loki", func(st outputStatus) bool { return st.SentTotal == 1 })

	stream := waitLokiStream(t, base, tenant, fmt.Sprintf(`{e2e_marker=%q}`, marker))
	assert.Equal(t, "e2e", stream.Stream["proc_name"])
	assert.Equal(t, "warning", stream.Stream["level"])
	assert.Equal(t, "e2e event "+marker, stream.Values[0][1])
}

// extra_labels was renamed to label_fields, and a field that does not make a label name is refused.
func TestLokiRefusesOldAndInvalidLabels(t *testing.T) {
	base := requireEnv(t, lokiURLEnv)
	logs := startSidekickFails(t, fmt.Sprintf("loki:\n  host: %q\n  extra_labels: proc.name\n", base))
	assert.Contains(t, logs, "unknown keys")
	logs = startSidekickFails(t, fmt.Sprintf("loki:\n  host: %q\n  label_fields: [proc-name]\n", base))
	assert.Contains(t, logs, "does not make a valid label name")
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

func TestLokiWrongBasePathFailsStartup(t *testing.T) {
	base := requireEnv(t, lokiURLEnv)
	logs := startSidekickFails(t, fmt.Sprintf("loki:\n  host: %q\n  base_path: /e2e-missing\n  tenant: e2e-falco\n", base))
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "HTTP 404")
}

// The readiness probe cannot detect a wrong push endpoint.
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

// An unreachable destination at startup is treated as transient.
func TestLokiUnreachableStartsDegraded(t *testing.T) {
	sk := startSidekick(t, fmt.Sprintf("loki:\n  host: %q\n", "http://127.0.0.1:19098"))
	st := sk.status(t, "loki")
	assert.Equal(t, "degraded", st.Status)
	assert.Contains(t, st.LastWarning, "health check failed before start")
}
