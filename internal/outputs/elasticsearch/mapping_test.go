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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
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
	require.Error(t, err)
	assert.Contains(t, err.Error(), "index template create")
	assert.Contains(t, err.Error(), "HTTP 403 Forbidden")
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
}

func TestTextWithKeyword(t *testing.T) {
	m := textWithKeyword(512)

	assert.Equal(t, "text", m["type"])
	fields := m["fields"].(map[string]any)
	kw := fields["keyword"].(map[string]any)
	assert.Equal(t, "keyword", kw["type"])
	assert.EqualValues(t, 512, kw["ignore_above"])
}
