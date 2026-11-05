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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// esServer is an Elasticsearch or OpenSearch cluster reached with the credentials and CA falcosidekick uses.
type esServer struct {
	client   *http.Client
	url      string
	username string
	password string
	caFile   string
}

func newESServer(t *testing.T) *esServer {
	t.Helper()
	es := &esServer{
		client:   httpClient,
		url:      strings.TrimSuffix(requireEnv(t, "FALCOSIDEKICK_E2E_ES_URL"), "/"),
		username: os.Getenv("FALCOSIDEKICK_E2E_ES_USERNAME"),
		password: os.Getenv("FALCOSIDEKICK_E2E_ES_PASSWORD"),
		caFile:   os.Getenv("FALCOSIDEKICK_E2E_ES_CA_FILE"),
	}
	if es.caFile != "" {
		pem, err := os.ReadFile(es.caFile)
		require.NoError(t, err)
		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(pem), "no certificate in %s", es.caFile)
		es.client = &http.Client{Timeout: httpClient.Timeout, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}}
	}
	return es
}

func (es *esServer) outputs(index, extra string) string {
	yaml := fmt.Sprintf("elasticsearch:\n  host: %q\n  index: %q\n", es.url, index)
	if es.username != "" {
		yaml += fmt.Sprintf("  username: %q\n  password: %q\n", es.username, es.password)
	}
	if es.caFile != "" {
		yaml += fmt.Sprintf("  tls:\n    ca_file: %q\n", es.caFile)
	}
	return yaml + extra
}

func (es *esServer) do(t *testing.T, method, path, body string) (status int, decoded map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, es.url+path, bytes.NewBufferString(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if es.username != "" {
		req.SetBasicAuth(es.username, es.password)
	}
	resp, err := es.client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp.StatusCode, decoded
}

// deleteIndices deletes by name because Elasticsearch 8+ refuses wildcard deletes by default.
func (es *esServer) deleteIndices(t *testing.T, pattern string) {
	t.Helper()
	for name := range es.indices(t, pattern) {
		es.do(t, http.MethodDelete, "/"+name, "")
	}
}

func (es *esServer) indices(t *testing.T, pattern string) map[string]any {
	t.Helper()
	status, body := es.do(t, http.MethodGet, "/"+pattern+"/_settings?allow_no_indices=true&expand_wildcards=open", "")
	require.Equal(t, http.StatusOK, status, body)
	return body
}

func (es *esServer) search(t *testing.T, index, marker string) []map[string]any {
	t.Helper()
	es.do(t, http.MethodPost, "/"+index+"/_refresh", "")
	query := fmt.Sprintf(`{"size":100,"query":{"match_phrase":{"output_fields.e2e.marker":%q}}}`, marker)
	status, body := es.do(t, http.MethodPost, "/"+index+"/_search", query)
	require.Equal(t, http.StatusOK, status, body)
	raw := body["hits"].(map[string]any)["hits"].([]any)
	hits := make([]map[string]any, len(raw))
	for i, hit := range raw {
		hits[i] = hit.(map[string]any)
	}
	return hits
}

func (es *esServer) count(t *testing.T, index string) int {
	t.Helper()
	es.do(t, http.MethodPost, "/"+index+"/_refresh", "")
	status, body := es.do(t, http.MethodGet, "/"+index+"/_count", "")
	require.Equal(t, http.StatusOK, status, body)
	return int(body["count"].(float64))
}

func (es *esServer) freshIndex(t *testing.T, marker string) string {
	t.Helper()
	index := "fsk-e2e-es-" + marker
	t.Cleanup(func() { es.do(t, http.MethodDelete, "/"+index, "") })
	return index
}

func TestElasticsearchIndexesEvent(t *testing.T) {
	es := newESServer(t)
	marker := newMarker(t)
	index := es.freshIndex(t, marker)
	sk := startSidekick(t, es.outputs(index, "  index_suffix: none\n"))

	sk.postEvent(t, marker)
	st := sk.waitStatus(t, "elasticsearch", func(st outputStatus) bool { return st.SentTotal == 1 })
	assert.Zero(t, st.FailedTotal)
	assert.Zero(t, st.DroppedTotal)

	hits := es.search(t, index, marker)
	require.Len(t, hits, 1)
	source := hits[0]["_source"].(map[string]any)
	require.NotEmpty(t, source["uuid"])
	assert.Equal(t, source["uuid"], hits[0]["_id"], "document _id is the event uuid")
	assert.Equal(t, "E2E "+marker, source["rule"])
	assert.Equal(t, "warning", source["priority"])
	assert.Equal(t, "syscall", source["source"])
	assert.Equal(t, "e2e-host", source["hostname"])
	assert.Equal(t, "e2e event "+marker, source["output"])
	assert.Equal(t, marker, source["output_fields"].(map[string]any)["e2e.marker"])
	timestamp, ok := source["@timestamp"].(string)
	require.True(t, ok, "@timestamp is a string: %v", source["@timestamp"])
	_, err := time.Parse(time.RFC3339Nano, timestamp)
	require.NoError(t, err)

	_, mapping := es.do(t, http.MethodGet, "/"+index+"/_mapping", "")
	properties := mapping[index].(map[string]any)["mappings"].(map[string]any)["properties"].(map[string]any)
	assert.Equal(t, "date", properties["@timestamp"].(map[string]any)["type"])
}

func TestElasticsearchBatchesEvents(t *testing.T) {
	es := newESServer(t)
	marker := newMarker(t)
	index := es.freshIndex(t, marker)
	sk := startSidekick(t, es.outputs(index, `  index_suffix: none
  runtime:
    batching:
      enabled: true
      batch_size: 5
      flush_interval: 500ms
`))

	for range 5 {
		sk.postEvent(t, marker)
	}
	st := sk.waitStatus(t, "elasticsearch", func(st outputStatus) bool { return st.SentTotal == 5 })
	assert.Zero(t, st.FailedTotal)

	hits := es.search(t, index, marker)
	require.Len(t, hits, 5)
	ids := map[any]bool{}
	for _, hit := range hits {
		assert.Equal(t, hit["_source"].(map[string]any)["uuid"], hit["_id"])
		ids[hit["_id"]] = true
	}
	assert.Len(t, ids, 5, "every event has its own document")
	assert.Equal(t, 5, es.count(t, index))
}

func TestElasticsearchReportsRejectedEvent(t *testing.T) {
	tests := []struct {
		name    string
		runtime string
		error   string
	}{
		{name: "single", error: "HTTP 400"},
		{
			name:    "bulk",
			runtime: "  runtime:\n    batching:\n      enabled: true\n      batch_size: 1\n      flush_interval: 100ms\n",
			error:   "bulk indexed 0/1, 1 failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := newESServer(t)
			marker := newMarker(t)
			index := es.freshIndex(t, marker)
			status, body := es.do(t, http.MethodPut, "/"+index,
				`{"mappings":{"dynamic":"strict","properties":{"@timestamp":{"type":"date"}}}}`)
			require.Equal(t, http.StatusOK, status, body)
			sk := startSidekick(t, es.outputs(index, "  index_suffix: none\n"+tt.runtime))

			sk.postEvent(t, marker)
			st := sk.waitStatus(t, "elasticsearch", func(st outputStatus) bool { return st.FailedTotal == 1 })
			assert.Zero(t, st.SentTotal)
			assert.Contains(t, st.LastError, tt.error)
			assert.Zero(t, es.count(t, index))
		})
	}
}

func TestElasticsearchCreatesIndexTemplate(t *testing.T) {
	es := newESServer(t)
	marker := newMarker(t)
	prefix := "fsk-e2e-es-tpl-" + marker
	t.Cleanup(func() {
		es.deleteIndices(t, prefix+"-*")
		es.do(t, http.MethodDelete, "/_index_template/"+prefix, "")
	})
	sk := startSidekick(t, es.outputs(prefix, `  create_index_template: true
  number_of_shards: 1
  number_of_replicas: 0
`))

	status, body := es.do(t, http.MethodGet, "/_index_template/"+prefix, "")
	require.Equal(t, http.StatusOK, status, "template exists once falcosidekick is ready: %v", body)
	assert.Contains(t, esJSON(t, body), fmt.Sprintf(`"index_patterns":[%q]`, prefix+"-*"))

	sk.postEvent(t, marker)
	sk.waitStatus(t, "elasticsearch", func(st outputStatus) bool { return st.SentTotal == 1 })

	created := es.indices(t, prefix+"-*")
	require.Len(t, created, 1)
	var index string
	for name := range created {
		index = name
	}
	assert.Regexp(t, `^`+prefix+`-\d{4}\.\d{2}\.\d{2}$`, index, "daily suffix")
	settings := esJSON(t, created[index])
	assert.Contains(t, settings, `"number_of_shards":"1"`)
	assert.Contains(t, settings, `"number_of_replicas":"0"`)

	_, mapping := es.do(t, http.MethodGet, "/"+index+"/_mapping", "")
	mapped := esJSON(t, mapping)
	assert.Contains(t, mapped, `"uuid":{"type":"keyword"}`)
	assert.Contains(t, mapped, `"output_fields_as_keyword"`)
	assert.Len(t, es.search(t, index, marker), 1)
}

// A wrong base path or rejected credentials stop startup.
func TestElasticsearchMisconfigurationFailsStartup(t *testing.T) {
	es := newESServer(t)
	t.Run("base_path", func(t *testing.T) {
		logs := startSidekickFails(t, es.outputs("fsk-e2e-es-unused", "  base_path: /e2e-missing\n"))
		assert.Contains(t, logs, "health check")
	})
	t.Run("password", func(t *testing.T) {
		if es.username == "" {
			t.Skip("server runs without authentication")
		}
		wrong := *es
		wrong.password = "wrong-" + newMarker(t)
		logs := startSidekickFails(t, wrong.outputs("fsk-e2e-es-unused", ""))
		assert.Contains(t, logs, "HTTP 401")
		assert.NotContains(t, logs, wrong.password)
	})
}

func esJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return string(data)
}
