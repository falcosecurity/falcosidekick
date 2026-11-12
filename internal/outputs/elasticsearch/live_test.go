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

//go:build integration

package elasticsearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

// FALCOSIDEKICK_ES_URL must be a disposable cluster: the test deletes the indices and templates it uses.
// The FALCOSIDEKICK_ES_USERNAME user must be able to create API keys unless FALCOSIDEKICK_ES_API_KEYS=false.
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
	resp, err := liveClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp.StatusCode, decoded
}

func liveClient(t *testing.T) *http.Client {
	t.Helper()
	caFile := os.Getenv("FALCOSIDEKICK_ES_CA_FILE")
	if caFile == "" {
		return http.DefaultClient
	}
	pem, err := os.ReadFile(caFile)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem))
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
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
	if _, explicit := cfg["tls"]; !explicit && os.Getenv("FALCOSIDEKICK_ES_CA_FILE") != "" {
		cfg["tls"] = map[string]any{"ca_file": os.Getenv("FALCOSIDEKICK_ES_CA_FILE")}
	}
	_, explicitKey := cfg["api_key"]
	tlsCfg, _ := cfg["tls"].(map[string]any)
	_, explicitCert := tlsCfg["cert_file"]
	if !explicitKey && !explicitCert {
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
		require.NoError(t, provision(liveDriver(t, cfg)))
		status, _ := liveRequest(t, base, http.MethodHead, "/_index_template/fsk-live-tpl", "")
		require.Equal(t, http.StatusOK, status)

		cfg["number_of_shards"] = 7
		require.NoError(t, provision(liveDriver(t, cfg)))
		_, body := liveRequest(t, base, http.MethodGet, "/_index_template/fsk-live-tpl", "")
		assert.Contains(t, mustJSON(t, body), `"number_of_shards":"1"`)
	})

	t.Run("daily index matches the template pattern", func(t *testing.T) {
		liveRequest(t, base, http.MethodDelete, "/fsk-live-tpl-*", "")
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-tpl"})
		evt := liveEvent("t1", 1)
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, []*event.Event{evt}))
		index := d.(*driver).resolveIndex(evt)
		_, body := liveRequest(t, base, http.MethodGet, "/"+index+"/_mapping", "")
		assert.Contains(t, mustJSON(t, body), `"uuid":{"type":"keyword"}`)
	})

	t.Run("template indexes dotted output fields", func(t *testing.T) {
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-tpl"})
		evt := liveEvent("dotted-1", nil)
		index := d.(*driver).resolveIndex(evt)
		liveRequest(t, base, http.MethodDelete, "/"+index, "")
		evt.OutputFields = map[string]any{"proc.name": "bash", "proc.pid": 4242}
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, []*event.Event{evt}))
		evt.UUID = "dotted-2"
		require.NoError(t, d.Send(ctx, evt))
		assert.Equal(t, 2.0, liveCount(t, base, index))

		_, body := liveRequest(t, base, http.MethodGet, "/"+index+"/_mapping", "")
		var mapping struct {
			Mappings struct {
				Properties struct {
					OutputFields struct {
						Properties struct {
							Proc struct {
								Properties map[string]struct {
									Type string `json:"type"`
								} `json:"properties"`
							} `json:"proc"`
						} `json:"properties"`
					} `json:"output_fields"`
				} `json:"properties"`
			} `json:"mappings"`
		}
		require.NoError(t, json.Unmarshal([]byte(mustJSON(t, body[index])), &mapping))
		proc := mapping.Mappings.Properties.OutputFields.Properties.Proc.Properties
		assert.Equal(t, "text", proc["name"].Type, "strings use the template mapping")
		assert.Equal(t, "long", proc["pid"].Type, "numbers keep their dynamic type")
	})

	t.Run("partial bulk failure and idempotent retry", func(t *testing.T) {
		liveRequest(t, base, http.MethodDelete, "/fsk-live", "")
		status, body := liveRequest(t, base, http.MethodPut, "/fsk-live",
			`{"mappings":{"properties":{"output_fields":{"properties":{"n":{"type":"long"}}}}}}`)
		require.Equal(t, http.StatusOK, status, body)
		batch := liveDriver(t, map[string]any{"host": base, "index": "fsk-live", "index_suffix": "none"}).(output.BatchSender)

		events := []*event.Event{liveEvent("a", 1), liveEvent("b", "not-a-number"), liveEvent("c", 3)}
		require.EqualError(t, batch.SendBatch(ctx, events), "elasticsearch response: bulk indexed 2/3, 1 rejected")
		require.EqualError(t, batch.SendBatch(ctx, events), "elasticsearch response: bulk indexed 2/3, 1 rejected")
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

	t.Run("data stream option creates its template and the stream", func(t *testing.T) {
		liveRequest(t, base, http.MethodDelete, "/_data_stream/fsk-live-dso", "")
		liveRequest(t, base, http.MethodDelete, "/_index_template/fsk-live-dso", "")
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-dso", "data_stream": true, "create_index_template": true})
		require.NoError(t, d.Init(ctx))
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, []*event.Event{liveEvent("dso-1", 1)}))
		require.NoError(t, d.Send(ctx, liveEvent("dso-2", 2)))
		noID := liveEvent("", 3)
		require.NoError(t, d.Send(ctx, noID))
		status, body := liveRequest(t, base, http.MethodGet, "/_data_stream/fsk-live-dso", "")
		require.Equal(t, http.StatusOK, status, body)
		assert.Equal(t, 3.0, liveCount(t, base, "fsk-live-dso"))
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
		if os.Getenv("FALCOSIDEKICK_ES_API_KEYS") == "false" {
			t.Skip("server without API keys")
		}
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
		cfg := map[string]any{
			"host": base, "index": "fsk-live-denied", "username": user, "password": password + "-wrong",
			"create_index_template": true, "number_of_shards": 1,
		}
		if caFile := os.Getenv("FALCOSIDEKICK_ES_CA_FILE"); caFile != "" {
			cfg["tls"] = map[string]any{"ca_file": caFile}
		}
		d, err := createOutput(cfg, output.Deps{Logger: slog.New(slog.DiscardHandler)})
		require.NoError(t, err)
		require.NoError(t, d.Init(ctx))
		require.ErrorContains(t, provision(d), "elasticsearch index template check: HTTP 401 Unauthorized")
		require.ErrorContains(t, d.(output.BatchSender).SendBatch(ctx, events("denied")), "HTTP 401")
		status, _ := liveRequest(t, base, http.MethodHead, "/_index_template/fsk-live-denied", "")
		assert.Equal(t, http.StatusNotFound, status)
		assert.NotContains(t, d.HealthCheck(ctx).Error(), password)
	})
}

func TestLiveElasticsearchTLS(t *testing.T) {
	base := liveURL(t)
	caFile := os.Getenv("FALCOSIDEKICK_ES_CA_FILE")
	if caFile == "" {
		t.Skip("FALCOSIDEKICK_ES_CA_FILE not set")
	}
	password := os.Getenv("FALCOSIDEKICK_ES_PASSWORD")
	ctx := context.Background()
	batch := []*event.Event{liveEvent("tls-1", 1)}

	t.Run("verified server certificate", func(t *testing.T) {
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-tls", "index_suffix": "none"})
		require.NoError(t, d.(output.BatchSender).SendBatch(ctx, batch))
	})

	t.Run("unknown authority is rejected", func(t *testing.T) {
		d := liveDriver(t, map[string]any{"host": base, "index": "fsk-live-tls", "index_suffix": "none", "tls": map[string]any{}})
		err := d.(output.BatchSender).SendBatch(ctx, batch)
		require.ErrorContains(t, err, "TLS certificate verification failed")
		if password != "" {
			assert.NotContains(t, err.Error(), password)
		}
	})

	t.Run("wrong server name is rejected", func(t *testing.T) {
		d := liveDriver(t, map[string]any{
			"host": base, "index": "fsk-live-tls", "index_suffix": "none",
			"tls": map[string]any{"ca_file": caFile, "server_name": "wrong.invalid"},
		})
		require.ErrorContains(t, d.(output.BatchSender).SendBatch(ctx, batch), "TLS certificate verification failed")
	})

	t.Run("client certificate", func(t *testing.T) {
		certFile, keyFile := os.Getenv("FALCOSIDEKICK_ES_CLIENT_CERT"), os.Getenv("FALCOSIDEKICK_ES_CLIENT_KEY")
		if certFile == "" {
			t.Skip("FALCOSIDEKICK_ES_CLIENT_CERT not set")
		}
		withCert := liveDriver(t, map[string]any{
			"host": base, "index": "fsk-live-mtls", "index_suffix": "none",
			"tls": map[string]any{"ca_file": caFile, "cert_file": certFile, "key_file": keyFile},
		})
		require.NoError(t, withCert.(output.BatchSender).SendBatch(ctx, []*event.Event{liveEvent("mtls-1", 1)}))
		require.NoError(t, withCert.Send(ctx, liveEvent("mtls-2", 1)))

		anonymous, err := createOutput(map[string]any{
			"host": base, "index": "fsk-live-mtls", "index_suffix": "none", "tls": map[string]any{"ca_file": caFile},
		}, output.Deps{Logger: slog.New(slog.DiscardHandler)})
		require.NoError(t, err)
		require.ErrorContains(t, anonymous.(output.BatchSender).SendBatch(ctx, []*event.Event{liveEvent("mtls-3", 1)}), "HTTP 401")
	})
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return string(data)
}
