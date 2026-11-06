// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
package shared_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/alertmanager"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
	"github.com/falcosecurity/falcosidekick/internal/outputs/cloudevents"
	"github.com/falcosecurity/falcosidekick/internal/outputs/datadog"
	"github.com/falcosecurity/falcosidekick/internal/outputs/discord"
	"github.com/falcosecurity/falcosidekick/internal/outputs/elasticsearch"
	"github.com/falcosecurity/falcosidekick/internal/outputs/grafanaoncall"
	"github.com/falcosecurity/falcosidekick/internal/outputs/loki"
	"github.com/falcosecurity/falcosidekick/internal/outputs/opsgenie"
	"github.com/falcosecurity/falcosidekick/internal/outputs/pagerduty"
	"github.com/falcosecurity/falcosidekick/internal/outputs/slack"
	"github.com/falcosecurity/falcosidekick/internal/outputs/talon"
	"github.com/falcosecurity/falcosidekick/internal/outputs/teams"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
)

var outputTypes = func() map[string]output.Type {
	types := make(map[string]output.Type, len(all.Types()))
	for _, kind := range all.Types() {
		types[kind.Name] = kind
	}
	return types
}()

type requestLog struct {
	uris []string
	mu   sync.Mutex
}

func (l *requestLog) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.uris = append(l.uris, r.Method+" "+r.RequestURI)
		l.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		switch {
		case strings.Contains(r.RequestURI, "/_bulk"):
			_, _ = w.Write([]byte(`{"errors":false,"items":[{"create":{"status":201}}]}`))
		case strings.Contains(r.RequestURI, "/services/"):
			_, _ = w.Write([]byte("ok"))
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func secretQuery() map[string]any {
	return map[string]any{
		"team":  map[string]any{"values": []string{"a b", "c"}},
		"token": map[string]any{"secrets": []string{"t&k"}},
	}
}

const wantQuery = "team=a+b&team=c&token=t%26k"

type httpTarget struct {
	config func(host string) map[string]any
	name   string
	send   string
	health string
	kind   output.Type
}

func TestDriversDeliverToExactTargets(t *testing.T) {
	for _, tt := range httpTargets {
		t.Run(tt.name, func(t *testing.T) {
			var log requestLog
			server := log.server(t)
			driver, err := tt.kind.New(tt.config(server.URL), output.Deps{})
			require.NoError(t, err)

			require.NoError(t, driver.Send(context.Background(), testutil.CreateValidEvent()))
			require.NoError(t, driver.HealthCheck(context.Background()))
			want := []string{tt.send}
			if tt.health != "" {
				want = append(want, tt.health)
			}
			assert.Equal(t, want, log.uris)
		})
	}
}

// A rejected event is not retried; an unavailable destination is.
func TestHTTPDriversClassifyRejections(t *testing.T) {
	for _, tt := range httpTargets {
		for status, permanent := range map[int]bool{http.StatusBadRequest: true, http.StatusServiceUnavailable: false} {
			t.Run(fmt.Sprintf("%s/%d", tt.name, status), func(t *testing.T) {
				_, server := testutil.NewRecorder(t, status, "")
				driver, err := tt.kind.New(tt.config(server.URL), output.Deps{})
				require.NoError(t, err)
				err = driver.Send(context.Background(), testutil.CreateValidEvent())
				require.Error(t, err)
				assert.Equal(t, permanent, output.IsPermanent(err), err.Error())
			})
		}
	}
}

var httpTargets = []httpTarget{
	{
		name: "webhook default endpoint", kind: webhook.OutputType,
		config: func(h string) map[string]any { return map[string]any{"host": h} },
		send:   "POST /",
	},
	{
		name: "webhook base and endpoint", kind: webhook.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/gw/", "endpoint": "/events", "query_params": secretQuery()}
		},
		send: "POST /gw/events?" + wantQuery,
	},
	{
		name: "webhook secret endpoint", kind: webhook.OutputType,
		config: func(h string) map[string]any { return map[string]any{"host": h, "secret_endpoint": "/hook/abc"} },
		send:   "POST /hook/abc",
	},
	{
		name: "slack", kind: slack.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/proxy", "secret_endpoint": "/services/T/B/X", "query_params": secretQuery()}
		},
		send: "POST /proxy/services/T/B/X?" + wantQuery,
	},
	{
		name: "loki default endpoint", kind: loki.OutputType,
		config: func(h string) map[string]any { return map[string]any{"host": h} },
		send:   "POST /loki/api/v1/push", health: "GET /ready",
	},
	{
		name: "loki base path", kind: loki.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/tenant", "endpoint": "/push", "query_params": secretQuery()}
		},
		send: "POST /tenant/push?" + wantQuery, health: "GET /tenant/ready?" + wantQuery,
	},
	{
		name: "elasticsearch", kind: elasticsearch.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{
				"host": h, "base_path": "/es", "index_suffix": "none", "pipeline": "a&b c", "query_params": secretQuery(),
			}
		},
		send: "PUT /es/falco/_create/test-uuid-001?pipeline=a%26b+c&" + wantQuery, health: "GET /es?" + wantQuery,
	},
	{
		name: "alertmanager default endpoint", kind: alertmanager.OutputType,
		config: func(h string) map[string]any { return map[string]any{"hosts": []string{h}} },
		send:   "POST /api/v2/alerts", health: "GET /-/healthy",
	},
	{
		name: "alertmanager base path with endpoint suffix in base", kind: alertmanager.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"hosts": []string{h}, "base_path": "/am/alerts", "endpoint": "/alerts", "query_params": secretQuery()}
		},
		send: "POST /am/alerts/alerts?" + wantQuery, health: "GET /am/alerts/-/healthy?" + wantQuery,
	},
	{
		name: "teams", kind: teams.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/wf", "secret_endpoint": "/workflows/1/triggers/manual/paths/invoke", "query_params": secretQuery()}
		},
		send: "POST /wf/workflows/1/triggers/manual/paths/invoke?" + wantQuery,
	},
	{
		name: "discord", kind: discord.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "secret_endpoint": "/api/webhooks/1/tok", "query_params": secretQuery()}
		},
		send: "POST /api/webhooks/1/tok?" + wantQuery + "&wait=true", health: "GET /api/webhooks/1/tok?" + wantQuery,
	},
	{
		name: "grafana oncall", kind: grafanaoncall.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/oncall", "secret_endpoint": "/integrations/v1/formatted_webhook/tok/", "query_params": secretQuery()}
		},
		send: "POST /oncall/integrations/v1/formatted_webhook/tok/?" + wantQuery,
	},
	{
		name: "talon", kind: talon.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/talon", "query_params": secretQuery()}
		},
		send: "POST /talon/?" + wantQuery, health: "GET /talon/healthz?" + wantQuery,
	},
	{
		name: "cloudevents", kind: cloudevents.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/ce", "endpoint": "/in", "query_params": secretQuery()}
		},
		send: "POST /ce/in?" + wantQuery,
	},
	{
		name: "pagerduty", kind: pagerduty.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/pd", "routing_key": "rk", "query_params": secretQuery()}
		},
		send: "POST /pd/v2/enqueue?" + wantQuery,
	},
	{
		name: "opsgenie", kind: opsgenie.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/og", "api_key": "k", "query_params": secretQuery()}
		},
		send: "POST /og/v2/alerts?" + wantQuery, health: "GET /og/v2/heartbeats?" + wantQuery,
	},
	{
		name: "datadog v1", kind: datadog.OutputType,
		config: func(h string) map[string]any {
			return map[string]any{"host": h, "base_path": "/dd", "api_key": "k", "query_params": secretQuery()}
		},
		send: "POST /dd/api/v1/events?" + wantQuery, health: "GET /dd/api/v1/validate?" + wantQuery,
	},
}

func TestBatchAndTemplateRoutes(t *testing.T) {
	events := []*event.Event{testutil.CreateValidEvent()}

	t.Run("loki batch", func(t *testing.T) {
		var log requestLog
		server := log.server(t)
		driver, err := loki.OutputType.New(map[string]any{"host": server.URL, "base_path": "/tenant"}, output.Deps{})
		require.NoError(t, err)
		require.NoError(t, driver.(output.BatchSender).SendBatch(context.Background(), events))
		assert.Equal(t, []string{"POST /tenant/loki/api/v1/push"}, log.uris)
	})

	t.Run("elasticsearch bulk", func(t *testing.T) {
		var log requestLog
		server := log.server(t)
		driver, err := elasticsearch.OutputType.New(map[string]any{
			"host": server.URL, "base_path": "/es", "pipeline": "a&b", "query_params": secretQuery(),
		}, output.Deps{})
		require.NoError(t, err)
		require.NoError(t, driver.(output.BatchSender).SendBatch(context.Background(), events))
		require.Len(t, log.uris, 1)
		target, err := url.ParseRequestURI(strings.TrimPrefix(log.uris[0], "POST "))
		require.NoError(t, err)
		assert.Equal(t, "/es/_bulk", target.Path)
		assert.Equal(t, url.Values{
			"filter_path": {"errors,items.*.status,items.*.error.type"},
			"pipeline":    {"a&b"},
			"team":        {"a b", "c"},
			"token":       {"t&k"},
		}, target.Query())
	})

	t.Run("elasticsearch template", func(t *testing.T) {
		var log requestLog
		server := log.server(t)
		driver, err := elasticsearch.OutputType.New(map[string]any{
			"host": server.URL, "base_path": "/es", "create_index_template": true,
			"number_of_shards": 1, "query_params": secretQuery(),
		}, output.Deps{})
		require.NoError(t, err)
		require.NoError(t, driver.Init(context.Background()))
		assert.Equal(t, []string{"HEAD /es/_index_template/falco?" + wantQuery}, log.uris)
	})

	t.Run("alertmanager fan-out", func(t *testing.T) {
		var first, second requestLog
		a, b := first.server(t), second.server(t)
		driver, err := alertmanager.OutputType.New(map[string]any{
			"hosts": []string{a.URL, b.URL}, "base_path": "/am", "query_params": secretQuery(),
		}, output.Deps{})
		require.NoError(t, err)
		require.NoError(t, driver.Send(context.Background(), testutil.CreateValidEvent()))
		want := []string{"POST /am/api/v2/alerts?" + wantQuery}
		assert.Equal(t, want, first.uris)
		assert.Equal(t, want, second.uris)
	})
}

func TestSlackHostDefault(t *testing.T) {
	driver, err := slack.OutputType.New(map[string]any{"secret_endpoint": "/services/T/B/X"}, output.Deps{})
	require.NoError(t, err)
	require.NotNil(t, driver)

	_, err = slack.OutputType.New(map[string]any{}, output.Deps{})
	require.ErrorContains(t, err, "secret_endpoint: is required")
	_, err = slack.OutputType.New(map[string]any{"endpoint": "/services/T/B/X", "secret_endpoint": "/x"}, output.Deps{})
	require.ErrorContains(t, err, "endpoint: is not supported; use secret_endpoint")
}

func TestElasticsearchRoutesAndReservedQuery(t *testing.T) {
	for _, field := range []string{"endpoint", "secret_endpoint"} {
		_, err := elasticsearch.OutputType.New(map[string]any{"host": "https://es", field: "/x"}, output.Deps{})
		require.ErrorContains(t, err, field+": is not supported")
	}
	for _, name := range []string{"filter_path", "pipeline"} {
		_, err := elasticsearch.OutputType.New(map[string]any{
			"host": "https://es", "query_params": map[string]any{name: map[string]any{"values": []string{"x"}}},
		}, output.Deps{})
		require.ErrorContains(t, err, "is set by the output")
	}
}

func TestAlertmanagerHostsAreOrigins(t *testing.T) {
	for _, host := range []string{"https://am/path", "https://am?x=1", "https://u:p@am"} {
		_, err := alertmanager.OutputType.New(map[string]any{"hosts": []string{host}}, output.Deps{})
		require.ErrorContains(t, err, "hosts: entry [0]")
	}
	_, err := alertmanager.OutputType.New(map[string]any{"hosts": []string{"https://am"}, "host": "https://am"}, output.Deps{})
	require.ErrorContains(t, err, "host: is not supported; use hosts")
}

func TestDriversRejectRemovedFields(t *testing.T) {
	tests := []struct {
		config map[string]any
		want   string
		kind   output.Type
	}{
		{kind: webhook.OutputType, config: map[string]any{"url": "https://h/x", "host": "https://h"}, want: "unknown keys: url"},
		{kind: loki.OutputType, config: map[string]any{"url": "https://h", "host": "https://h"}, want: "unknown keys: url"},
		{kind: elasticsearch.OutputType, config: map[string]any{"url": "https://h", "host": "https://h"}, want: "unknown keys: url"},
		{
			kind: slack.OutputType, config: map[string]any{"webhook_url": "https://h/x", "secret_endpoint": "/x"},
			want: "unknown keys: webhook_url",
		},
	}
	for _, tt := range tests {
		t.Run(tt.kind.Name, func(t *testing.T) {
			_, err := tt.kind.New(tt.config, output.Deps{})
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestDriverTargetFailureStaysSafe(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	path := filepath.Join(t.TempDir(), sentinel)
	require.NoError(t, os.WriteFile(path, []byte(sentinel), 0o600))
	driver, err := webhook.OutputType.New(map[string]any{
		"host": "http://127.0.0.1:1", "query_params": map[string]any{"t": map[string]any{"files": []string{path}}},
	}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))

	require.EqualError(t, driver.Send(context.Background(), testutil.CreateValidEvent()),
		"webhook target: cannot resolve target")
}

var commentedBlock = regexp.MustCompile(`(?m)^ {2}# ([a-z0-9]+):\n((?: {2}# {2}.*\n)+)`)

// exampleBlocks returns every output block of the example file, commented or not.
func exampleBlocks(t *testing.T, path string) map[string]map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var active struct {
		Outputs map[string]map[string]any `yaml:"outputs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &active))
	blocks := map[string]map[string]any{}
	for name, cfg := range active.Outputs {
		blocks[name] = cfg
	}
	for _, m := range commentedBlock.FindAllStringSubmatch(string(raw), -1) {
		body := regexp.MustCompile(`(?m)^ {2}# `).ReplaceAllString(m[2], "")
		var cfg map[string]any
		require.NoError(t, yaml.Unmarshal([]byte(body), &cfg), m[1])
		blocks[m[1]] = cfg
	}
	return blocks
}

func TestExampleOutputsConstruct(t *testing.T) {
	registered := make([]string, 0, len(all.Types()))
	for _, kind := range all.Types() {
		registered = append(registered, kind.Name)
	}
	for path, want := range map[string][]string{
		"../../../config_example_outputs.yaml": registered,
		"../../../hack/live-test/outputs.yaml": {"inmemory", "webhook"},
	} {
		blocks := exampleBlocks(t, path)
		for _, name := range want {
			t.Run(filepath.Base(filepath.Dir(path))+"/"+name, func(t *testing.T) {
				require.Contains(t, blocks, name)
				kind, ok := outputTypes[name]
				require.True(t, ok)
				_, err := kind.New(withSecretPlaceholders(blocks[name]), output.Deps{})
				require.NoError(t, err)
			})
		}
	}
}

// withSecretPlaceholders replaces each _file reference, as secret resolution would.
func withSecretPlaceholders(cfg map[string]any) map[string]any {
	result := make(map[string]any, len(cfg))
	for key, value := range cfg {
		if nested, ok := value.(map[string]any); ok {
			value = withSecretPlaceholders(nested)
		}
		if name, ok := strings.CutSuffix(key, "_file"); ok {
			key, value = name, "placeholder"
		}
		result[key] = value
	}
	return result
}

func TestV2MappingFixturesConstruct(t *testing.T) {
	raw, err := os.ReadFile("testdata/v2_v3_mapping.yaml")
	require.NoError(t, err)
	var cases []struct {
		V2     map[string]any `yaml:"v2"`
		V3     map[string]any `yaml:"v3"`
		Output string         `yaml:"output"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &cases))

	covered := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.Output, func(t *testing.T) {
			require.NotEmpty(t, tc.V2)
			_, err := outputTypes[tc.Output].New(tc.V3, output.Deps{})
			require.NoError(t, err)
			covered[tc.Output] = true
		})
	}
	assert.Equal(t, map[string]bool{
		"alertmanager": true, "elasticsearch": true, "loki": true, "slack": true, "webhook": true,
	}, covered)
}
