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

//go:build elasticsearch_live

package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

// Run with hack/elasticsearch-matrix.sh, or set FALCOSIDEKICK_ES_URL to a
// disposable cluster: the test deletes the indices and templates it uses.
// FALCOSIDEKICK_ES_USERNAME and FALCOSIDEKICK_ES_PASSWORD enable the
// authentication cases; the user must be able to create API keys.
func liveURL(t *testing.T) string {
	t.Helper()
	target := os.Getenv("FALCOSIDEKICK_ES_URL")
	if target == "" {
		t.Skip("FALCOSIDEKICK_ES_URL not set")
	}
	return strings.TrimSuffix(target, "/")
}

func liveRequest(t *testing.T, base, method, path, body string) (status int, decoded map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, base+path, bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if user := os.Getenv("FALCOSIDEKICK_ES_USERNAME"); user != "" {
		req.SetBasicAuth(user, os.Getenv("FALCOSIDEKICK_ES_PASSWORD"))
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp.StatusCode, decoded
}

func liveCount(t *testing.T, base, index string) float64 {
	t.Helper()
	liveRequest(t, base, http.MethodPost, "/"+index+"/_refresh", "")
	status, body := liveRequest(t, base, http.MethodGet, "/"+index+"/_count", "")
	require.Equal(t, http.StatusOK, status, body)
	return body["count"].(float64)
}

func liveEvent(id string, n any) *event.Event {
	evt := testutil.CreateValidEvent()
	evt.UUID = id
	evt.OutputFields = map[string]any{"n": n}
	return evt
}

func liveDriver(t *testing.T, cfg map[string]any) output.Driver {
	t.Helper()
	if _, explicit := cfg["api_key"]; !explicit {
		if user := os.Getenv("FALCOSIDEKICK_ES_USERNAME"); user != "" {
			cfg["username"] = user
			cfg["password"] = os.Getenv("FALCOSIDEKICK_ES_PASSWORD")
		}
	}
	d, err := createOutput(cfg, output.Deps{Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)
	return d
}

func TestLiveElasticsearch(t *testing.T) {
	base := liveURL(t)
	ctx := context.Background()

	t.Run("health check", func(t *testing.T) {
		require.NoError(t, liveDriver(t, map[string]any{"host": base}).HealthCheck(ctx))
	})

	t.Run("template created once and kept", func(t *testing.T) {
		liveRequest(t, base, http.MethodDelete, "/_index_template/fsk-live-tpl", "")
		cfg := map[string]any{
			"host": base, "index": "fsk-live-tpl", "create_index_template": true,
			"number_of_shards": 1, "number_of_replicas": 0,
		}
		require.NoError(t, liveDriver(t, cfg).Init(ctx))
		status, _ := liveRequest(t, base, http.MethodHead, "/_index_template/fsk-live-tpl", "")
		require.Equal(t, http.StatusOK, status)

		cfg["number_of_shards"] = 7
		require.NoError(t, liveDriver(t, cfg).Init(ctx))
		_, body := liveRequest(t, base, http.MethodGet, "/_index_template/fsk-live-tpl", "")
		assert.Contains(t, mustJSON(t, body), `"number_of_shards":"1"`)
	})

	t.Run("daily index matches the template pattern", func(t *testing.T) {
		liveRequest(t, base, http.MethodDelete, "/fsk-live-tpl-*", "")
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-tpl"})
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, []*event.Event{liveEvent("t1", 1)}))
		index := d.(*driver).resolveIndex()
		_, body := liveRequest(t, base, http.MethodGet, "/"+index+"/_mapping", "")
		assert.Contains(t, mustJSON(t, body), `"uuid":{"type":"keyword"}`)
	})

	t.Run("partial bulk failure and idempotent retry", func(t *testing.T) {
		liveRequest(t, base, http.MethodDelete, "/fsk-live", "")
		status, body := liveRequest(t, base, http.MethodPut, "/fsk-live",
			`{"mappings":{"properties":{"output_fields":{"properties":{"n":{"type":"long"}}}}}}`)
		require.Equal(t, http.StatusOK, status, body)
		batch := liveDriver(t, map[string]any{"host": base, "index": "fsk-live", "index_suffix": "none"}).(output.BatchSender)

		events := []*event.Event{liveEvent("a", 1), liveEvent("b", "not-a-number"), liveEvent("c", 3)}
		require.EqualError(t, batch.SendBatch(ctx, events), "elasticsearch: bulk indexed 2/3, 1 failed")
		require.EqualError(t, batch.SendBatch(ctx, events), "elasticsearch: bulk indexed 2/3, 1 failed")
		assert.Equal(t, 2.0, liveCount(t, base, "fsk-live"))

		require.NoError(t, batch.SendBatch(ctx, []*event.Event{liveEvent("a", 1), liveEvent("c", 3), liveEvent("d", 4)}))
		assert.Equal(t, 3.0, liveCount(t, base, "fsk-live"))
	})

	t.Run("single send is idempotent", func(t *testing.T) {
		liveRequest(t, base, http.MethodDelete, "/fsk-live-single", "")
		status, body := liveRequest(t, base, http.MethodPut, "/fsk-live-single",
			`{"mappings":{"properties":{"output_fields":{"properties":{"n":{"type":"long"}}}}}}`)
		require.Equal(t, http.StatusOK, status, body)
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-single", "index_suffix": "none", "pipeline": ""})
		require.NoError(t, d.Send(ctx, liveEvent("s1", 5)))
		require.NoError(t, d.Send(ctx, liveEvent("s1", 5)))
		require.Error(t, d.Send(ctx, liveEvent("s2", "bad")))
		assert.Equal(t, 1.0, liveCount(t, base, "fsk-live-single"))
	})

	t.Run("data stream accepts ids and deduplicates", func(t *testing.T) {
		liveRequest(t, base, http.MethodDelete, "/_data_stream/fsk-live-ds", "")
		liveRequest(t, base, http.MethodDelete, "/_index_template/fsk-live-ds", "")
		status, body := liveRequest(t, base, http.MethodPut, "/_index_template/fsk-live-ds",
			`{"index_patterns":["fsk-live-ds"],"data_stream":{},"priority":500,"template":{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}}`)
		require.Equal(t, http.StatusOK, status, body)
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-ds", "index_suffix": "none"})
		events := []*event.Event{liveEvent("x", 1), liveEvent("y", 2)}
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, events))
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, events))
		require.NoError(t, d.Send(ctx, liveEvent("z", 3)))
		require.NoError(t, d.Send(ctx, liveEvent("z", 3)))
		assert.Equal(t, 3.0, liveCount(t, base, "fsk-live-ds"))
	})

	t.Run("ingest pipeline is applied", func(t *testing.T) {
		status, body := liveRequest(t, base, http.MethodPut, "/_ingest/pipeline/fsk-live-pipe",
			`{"processors":[{"set":{"field":"pipeline_mark","value":"seen"}}]}`)
		require.Equal(t, http.StatusOK, status, body)
		liveRequest(t, base, http.MethodDelete, "/fsk-live-pipe", "")
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-pipe", "index_suffix": "none", "pipeline": "fsk-live-pipe"})
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, []*event.Event{liveEvent("p1", 1)}))
		require.NoError(t, d.Send(ctx, liveEvent("p2", 2)))
		liveRequest(t, base, http.MethodPost, "/fsk-live-pipe/_refresh", "")
		_, found := liveRequest(t, base, http.MethodGet, "/fsk-live-pipe/_count?q=pipeline_mark:seen", "")
		assert.Equal(t, 2.0, found["count"])
	})
}

func TestLiveElasticsearchAuthentication(t *testing.T) {
	base := liveURL(t)
	user, password := os.Getenv("FALCOSIDEKICK_ES_USERNAME"), os.Getenv("FALCOSIDEKICK_ES_PASSWORD")
	if user == "" {
		t.Skip("FALCOSIDEKICK_ES_USERNAME not set")
	}
	ctx := context.Background()
	events := func(id string) []*event.Event { return []*event.Event{liveEvent(id, 1)} }

	t.Run("basic auth", func(t *testing.T) {
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-auth", "index_suffix": "none"})
		require.NoError(t, d.HealthCheck(ctx))
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, events("basic-batch")))
		require.NoError(t, d.Send(ctx, liveEvent("basic-single", 1)))
	})

	t.Run("api key", func(t *testing.T) {
		status, body := liveRequest(t, base, http.MethodPost, "/_security/api_key", `{"name":"fsk-live"}`)
		require.Equal(t, http.StatusOK, status, body)
		key, ok := body["encoded"].(string)
		require.True(t, ok, body)
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-auth", "index_suffix": "none", "api_key": key})
		require.NoError(t, d.HealthCheck(ctx))
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, events("key-batch")))
		require.NoError(t, d.Send(ctx, liveEvent("key-single", 1)))
		assert.Equal(t, 4.0, liveCount(t, base, "fsk-live-auth"))
	})

	t.Run("wrong credentials fail and never create the template", func(t *testing.T) {
		liveRequest(t, base, http.MethodDelete, "/_index_template/fsk-live-denied", "")
		d, err := createOutput(map[string]any{
			"host": base, "index": "fsk-live-denied", "username": user, "password": password + "-wrong",
			"create_index_template": true, "number_of_shards": 1,
		}, output.Deps{Logger: slog.New(slog.DiscardHandler)})
		require.NoError(t, err)
		require.ErrorContains(t, d.Init(ctx), "index template check: elasticsearch response: HTTP 401 Unauthorized")
		require.ErrorContains(t, d.(output.BatchSender).SendBatch(ctx, events("denied")), "HTTP 401")
		status, _ := liveRequest(t, base, http.MethodHead, "/_index_template/fsk-live-denied", "")
		assert.Equal(t, http.StatusNotFound, status)
		assert.NotContains(t, d.HealthCheck(ctx).Error(), password)
	})
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return string(data)
}
