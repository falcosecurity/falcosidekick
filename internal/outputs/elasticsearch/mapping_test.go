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

package elasticsearch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

func TestInitTemplateSafeRequestError(t *testing.T) {
	d := &driver{cfg: config{
		HTTPTargetConfig: shared.HTTPTargetConfig{Host: "https://es.invalid", BasePath: "/PATH_SECRET\n%zz"},
		Index:            "falco",
	}}
	err := d.createIndexTemplate(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "elasticsearch target: cannot resolve target")
	assert.NotContains(t, err.Error(), "PATH_SECRET")
	var diagnostic *shared.DeliveryError
	assert.ErrorAs(t, err, &diagnostic)
}

func TestInitTemplateSafeHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("TEMPLATE_RESPONSE_SECRET"))
	}))
	t.Cleanup(server.Close)
	d, err := createOutput(map[string]any{
		"host":                  server.URL,
		"base_path":             "/PATH_SECRET",
		"create_index_template": true,
		"number_of_shards":      1,
	}, output.Deps{})
	require.NoError(t, err)
	err = d.Init(context.Background())
	require.ErrorIs(t, err, output.ErrMisconfigured)
	assert.Equal(t, "elasticsearch index template create: HTTP 403 Forbidden", err.Error())
	assert.NotContains(t, err.Error(), "TEMPLATE_RESPONSE_SECRET")
	assert.NotContains(t, err.Error(), "PATH_SECRET")
	var diagnostic *shared.DeliveryError
	assert.ErrorAs(t, err, &diagnostic)
}

func TestInitTemplateAlreadyExists(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver, err := createOutput(map[string]any{
		"host":                  server.URL,
		"create_index_template": true,
		"number_of_shards":      3,
		"number_of_replicas":    1,
	}, output.Deps{})
	require.NoError(t, err)

	require.NoError(t, driver.Init(context.Background()))

	assert.Contains(t, methods, http.MethodHead)
	for _, m := range methods {
		assert.NotEqual(t, http.MethodPut, m, "PUT must not be sent when template exists")
	}
}

func TestInitTemplateCreated(t *testing.T) {
	var capturedPutBody []byte
	var capturedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPut {
			capturedURL = r.URL.Path
			capturedPutBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver, err := createOutput(map[string]any{
		"host":                  server.URL,
		"create_index_template": true,
		"number_of_shards":      5,
		"number_of_replicas":    2,
	}, output.Deps{})
	require.NoError(t, err)

	require.NoError(t, driver.Init(context.Background()))

	assert.Contains(t, capturedURL, "_index_template", "must use composable _index_template API")
	require.NotEmpty(t, capturedPutBody)

	var tmpl map[string]any
	require.NoError(t, json.Unmarshal(capturedPutBody, &tmpl))
	assert.Contains(t, tmpl, "index_patterns")

	template, ok := tmpl["template"].(map[string]any)
	require.True(t, ok, "composable template must have 'template' wrapper")

	settings, ok := template["settings"].(map[string]any)
	require.True(t, ok)
	assert.EqualValues(t, 5, settings["number_of_shards"])
	assert.EqualValues(t, 2, settings["number_of_replicas"])

	mappings, ok := template["mappings"].(map[string]any)
	require.True(t, ok, "template must include mappings")
	assert.Contains(t, mappings, "properties")
	assert.Contains(t, mappings, "dynamic_templates")
}

func TestInitTemplateSkipped(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	driver, err := createOutput(map[string]any{
		"host":                  server.URL,
		"create_index_template": false,
	}, output.Deps{})
	require.NoError(t, err)

	require.NoError(t, driver.Init(context.Background()))
	assert.False(t, called)
}

// A delivery waiting for another worker's template check leaves when its own context ends.
func TestTemplateWaitFollowsTheContext(t *testing.T) {
	server := testutil.HangingHTTPServer(t)
	drv, err := createOutput(map[string]any{"host": server.URL, "create_index_template": true}, output.Deps{})
	require.NoError(t, err)
	d := drv.(*driver)

	holder, release := context.WithCancel(context.Background())
	t.Cleanup(release)
	started := make(chan struct{})
	go func() {
		close(started)
		_ = d.ensureTemplate(holder)
	}()
	<-started
	held := func() bool {
		if d.templateGate.TryAcquire(1) {
			d.templateGate.Release(1)
			return false
		}
		return true
	}
	require.Eventually(t, held, time.Second, time.Millisecond, "the first check holds the gate")

	err = testutil.RequireReturnsOnCancel(t, "ensureTemplate", d.ensureTemplate)
	assert.Equal(t, "elasticsearch index template check: timeout (deadline exceeded)", err.Error())
	assert.False(t, output.IsPermanent(err))
}

func TestInitTemplateCreatesOnlyWhenAbsent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wantErr string
		head    int
		wantPut bool
	}{
		{name: "exists", head: http.StatusOK},
		{name: "absent", head: http.StatusNotFound, wantPut: true},
		{name: "unauthorized", head: http.StatusUnauthorized, wantErr: "elasticsearch index template check: HTTP 401 Unauthorized"},
		{name: "server error is left to the first delivery", head: http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var puts int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					puts++
					return
				}
				w.WriteHeader(tc.head)
			}))
			t.Cleanup(server.Close)
			d, err := createOutput(map[string]any{"host": server.URL, "create_index_template": true, "number_of_shards": 1}, output.Deps{})
			require.NoError(t, err)

			err = d.Init(context.Background())
			if tc.wantErr != "" {
				require.ErrorIs(t, err, output.ErrMisconfigured)
				assert.Contains(t, err.Error(), tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantPut, puts == 1)
		})
	}
}

func TestTemplateCreatedBeforeFirstDelivery(t *testing.T) {
	var up atomic.Bool
	var requests []string
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case !up.Load():
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	t.Cleanup(server.Close)
	d, err := createOutput(map[string]any{"host": server.URL, "create_index_template": true, "number_of_shards": 1}, output.Deps{})
	require.NoError(t, err)

	require.NoError(t, d.Init(context.Background()), "a transient error does not fail startup")
	require.Error(t, d.Send(context.Background(), testutil.CreateValidEvent()), "no delivery before the template")
	for _, req := range requests {
		assert.NotContains(t, req, "_create", "nothing indexed while the template is missing")
	}

	up.Store(true)
	mu.Lock()
	requests = nil
	mu.Unlock()
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	assert.Equal(t, []string{
		"HEAD /_index_template/falco", "PUT /_index_template/falco",
		"PUT /falco-" + testutil.CreateValidEvent().Time.UTC().Format("2006.01.02") + "/_create/test-uuid-001",
		"PUT /falco-" + testutil.CreateValidEvent().Time.UTC().Format("2006.01.02") + "/_create/test-uuid-001",
	}, requests, "the template is created once, before the first document")
}

func TestBuildMappingsContainsExpectedFields(t *testing.T) {
	m := buildMappings()

	props, ok := m["properties"].(map[string]any)
	require.True(t, ok)

	expectedFields := []string{"@timestamp", "uuid", "rule", "output", "priority", "source", "hostname", "tags"}
	for _, field := range expectedFields {
		assert.Contains(t, props, field, "mapping must define %s", field)
	}

	timestamp, ok := props["@timestamp"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "date", timestamp["type"], "@timestamp must be date type")
}

func TestBuildMappingsDynamicTemplate(t *testing.T) {
	m := buildMappings()

	dt, ok := m["dynamic_templates"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, dt, 1)

	tmpl := dt[0]["output_fields_as_keyword"].(map[string]any)
	assert.Equal(t, "output_fields.*", tmpl["path_match"])
	// Otherwise the objects of dotted names are mapped as text and every event is rejected.
	assert.Equal(t, "string", tmpl["match_mapping_type"])
}

func TestInitTemplateShardSettings(t *testing.T) {
	for _, tc := range []struct {
		config       map[string]any
		wantSettings map[string]any
		name         string
		wantErr      string
	}{
		{name: "absent leaves the cluster default", config: map[string]any{}},
		{name: "null leaves the cluster default", config: map[string]any{"number_of_shards": nil, "number_of_replicas": nil}},
		{name: "explicit shards", config: map[string]any{"number_of_shards": 1}, wantSettings: map[string]any{"number_of_shards": 1.0}},
		{name: "explicit replicas", config: map[string]any{"number_of_replicas": 2}, wantSettings: map[string]any{"number_of_replicas": 2.0}},
		{name: "explicit zero replicas", config: map[string]any{"number_of_replicas": 0}, wantSettings: map[string]any{"number_of_replicas": 0.0}},
		{name: "string values", config: map[string]any{"number_of_shards": "2", "number_of_replicas": "0"},
			wantSettings: map[string]any{"number_of_shards": 2.0, "number_of_replicas": 0.0}},
		{name: "explicit zero shards", config: map[string]any{"number_of_shards": 0}, wantErr: "number_of_shards: must be > 0 when create_index_template is true"},
		{name: "negative shards", config: map[string]any{"number_of_shards": -1}, wantErr: "number_of_shards: must be > 0 when create_index_template is true"},
		{name: "negative replicas", config: map[string]any{"number_of_replicas": -1}, wantErr: "number_of_replicas: must be >= 0 when create_index_template is true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var template map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				var tmpl struct {
					Template map[string]any `json:"template"`
				}
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&tmpl))
				template = tmpl.Template
			}))
			t.Cleanup(server.Close)
			tc.config["host"] = server.URL
			tc.config["create_index_template"] = true

			d, err := createOutput(tc.config, output.Deps{})
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.NoError(t, d.Init(context.Background()))
			require.Contains(t, template, "mappings")
			if tc.wantSettings == nil {
				assert.NotContains(t, template, "settings", "no settings: the cluster default applies")
				return
			}
			assert.Equal(t, tc.wantSettings, template["settings"])
		})
	}
}

func TestInitTemplateDataStream(t *testing.T) {
	for _, tc := range []struct {
		config       map[string]any
		name         string
		wantPattern  string
		wantTemplate string
		wantStream   bool
	}{
		{name: "dated index", config: map[string]any{"index": "falco"}, wantPattern: "falco-*", wantTemplate: "/_index_template/falco"},
		{name: "data stream", config: map[string]any{"index": "logs-falco-default", "data_stream": true},
			wantPattern: "logs-falco-default", wantStream: true, wantTemplate: "/_index_template/logs-falco-default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tmpl map[string]any
			var path string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				path = r.URL.Path
				assert.NoError(t, json.NewDecoder(r.Body).Decode(&tmpl))
			}))
			t.Cleanup(server.Close)
			tc.config["host"] = server.URL
			tc.config["create_index_template"] = true
			d, err := createOutput(tc.config, output.Deps{})
			require.NoError(t, err)
			require.NoError(t, d.Init(context.Background()))

			assert.Equal(t, tc.wantTemplate, path)
			assert.Equal(t, []any{tc.wantPattern}, tmpl["index_patterns"])
			stream, has := tmpl["data_stream"]
			assert.Equal(t, tc.wantStream, has)
			if tc.wantStream {
				assert.Equal(t, map[string]any{}, stream)
			}
		})
	}
}

func TestBuildMappingsHostnameIsKeyword(t *testing.T) {
	props := buildMappings()["properties"].(map[string]any)
	assert.Equal(t, map[string]any{"type": "keyword"}, props["hostname"])
}

func TestShardSettingsIgnoredWithoutTemplate(t *testing.T) {
	_, err := createOutput(map[string]any{"host": "https://es.example", "number_of_shards": 0, "number_of_replicas": -1}, output.Deps{})
	require.NoError(t, err)
}

func TestTextWithKeyword(t *testing.T) {
	m := textWithKeyword(512)

	assert.Equal(t, "text", m["type"])
	fields := m["fields"].(map[string]any)
	kw := fields["keyword"].(map[string]any)
	assert.Equal(t, "keyword", kw["type"])
	assert.EqualValues(t, 512, kw["ignore_above"])
}
