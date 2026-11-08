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
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/slack"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
)

func putOutput(t *testing.T, rig *mutationTestRig, name, body string) (status int, response string) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/"+name, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(raw)
}

func TestTargetSecretsStayOutOfAPIAndSurvivePartialPUT(t *testing.T) {
	const pathSecret, querySecret = "path-sentinel", "query-sentinel"
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	db := database.NewMemory()
	rig := buildMutationRig(t, db, cat, true)

	status, body := putOutput(t, rig, "webhook", `{"config":{
		"host":"https://collector.example","base_path":"/gw","secret_endpoint":"/hook/`+pathSecret+`",
		"query_params":{"token":{"values":["public"],"secrets":["`+querySecret+`"]}}}}`)
	require.Equal(t, http.StatusOK, status, body)
	assert.NotContains(t, body, pathSecret)
	assert.NotContains(t, body, querySecret)

	var masked struct {
		Config       map[string]any  `json:"config"`
		SecretFields map[string]bool `json:"secret_fields"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &masked))
	assert.Equal(t, "https://collector.example", masked.Config["host"])
	assert.Equal(t, "/gw", masked.Config["base_path"])
	assert.NotContains(t, masked.Config, "secret_endpoint")
	assert.True(t, masked.SecretFields["/secret_endpoint"])
	assert.True(t, masked.SecretFields["/query_params/token/secrets"])

	status, body = putOutput(t, rig, "webhook", `{"config":{"method":"PUT"}}`)
	require.Equal(t, http.StatusOK, status, body)
	stored, err := db.GetOutputConfig(t.Context(), "webhook")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "/hook/"+pathSecret, stored.Config["secret_endpoint"])
	assert.Equal(t, []any{querySecret}, stored.Config["query_params"].(map[string]any)["token"].(map[string]any)["secrets"])
	assert.Equal(t, "PUT", stored.Config["method"])
}

func TestPUTRejectsTargetViolationsAs400(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	cat, err := catalog.New([]output.Type{webhook.OutputType, slack.OutputType})
	require.NoError(t, err)
	for _, tt := range []struct {
		name   string
		output string
		body   string
		want   string
	}{
		{"removed url", "webhook", `{"config":{"host":"https://h","url":"https://h/` + sentinel + `"}}`, "unknown keys: url"},
		{"removed webhook_url", "slack", `{"config":{"secret_endpoint":"/x","webhook_url":"https://h/` + sentinel + `"}}`, "unknown keys: webhook_url"},
		{"both endpoints", "webhook", `{"config":{"host":"https://h","endpoint":"/a","secret_endpoint":"/` + sentinel + `"}}`, "cannot be combined"},
		{"host with path", "webhook", `{"config":{"host":"https://h/` + sentinel + `"}}`, "host: must be scheme, host and port only"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rig := buildMutationRig(t, database.NewMemory(), cat, true)
			status, body := putOutput(t, rig, tt.output, tt.body)
			assert.Equal(t, http.StatusBadRequest, status, body)
			assert.Contains(t, body, tt.want)
			assert.NotContains(t, body, sentinel)
		})
	}
}
