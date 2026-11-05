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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	databasetestutil "github.com/falcosecurity/falcosidekick/internal/database/testutil"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
)

func TestHandlePipelineStatus_NoOutputs(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/status", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"outputs":[]`, "empty status must serialize as empty slice, not null")
}

func TestHandlePipelineStatus_WithOutputs(t *testing.T) {
	cfg := testutil.DefaultRuntimeConfig()
	out1 := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &cfg, nil)
	out2 := pipeline.NewOutput(&testutil.MockDriver{DriverName: "elasticsearch"}, &cfg, nil)
	srv := buildTestServer(t, []*pipeline.Output{out1, out2})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/status", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got struct {
		Outputs []pipeline.OutputStatus `json:"outputs"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Outputs, 2)

	names := []string{got.Outputs[0].Name, got.Outputs[1].Name}
	assert.ElementsMatch(t, []string{"slack", "elasticsearch"}, names)
}

func TestHandlePipelineStatusByName_Hit(t *testing.T) {
	cfg := testutil.DefaultRuntimeConfig()
	out := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &cfg, nil)
	srv := buildTestServer(t, []*pipeline.Output{out})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/status/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got pipeline.OutputStatus
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "slack", got.Name)
}

func TestHandlePipelineStatusByName_Miss(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/status/missing", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 404, resp.StatusCode)
}

func TestHandlePipelineOutputs_Masked(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"elasticsearch": {"host": "https://es:9200", "password": "hunter2"},
			"slack":         {"host": "https://hooks.slack.com/x", "channel": "#c"},
		},
	}))
	cat, err := catalog.New([]output.Type{
		{
			Name: "elasticsearch",
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: "elasticsearch"}, nil
			},
			Schema: output.Schema{Fields: []output.SchemaField{
				{Name: "host", Type: "string"},
				{Name: "password", Type: "string", Secret: true},
			}},
		},
		{
			Name: "slack",
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: "slack"}, nil
			},
			Schema: output.Schema{Fields: []output.SchemaField{
				{Name: "host", Type: "string"},
				{Name: "channel", Type: "string"},
			}},
		},
	})
	require.NoError(t, err)

	srv := buildTestServerWithDBAndCatalog(t, db, cat)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)

	var got map[string]outputConfigResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))

	assert.NotContains(t, got["elasticsearch"].Config, "password")
	assert.True(t, got["elasticsearch"].SecretFields["/password"])
	assert.Equal(t, "https://es:9200", got["elasticsearch"].Config["host"])
	assert.Equal(t, "https://hooks.slack.com/x", got["slack"].Config["host"])
}

func TestHandlePipelineOutputs_NoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandlePipelineOutputs_DBError(t *testing.T) {
	srv := buildTestServerWithDB(t, allReadsFailDB())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "db failure")
}

func TestHandlePipelineOutputByName_Hit(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"elasticsearch": {"host": "https://es:9200", "password": "hunter2"},
		},
	}))
	cat, err := catalog.New([]output.Type{{
		Name: "elasticsearch",
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "elasticsearch"}, nil
		},
		Schema: output.Schema{Fields: []output.SchemaField{
			{Name: "host", Type: "string"},
			{Name: "password", Type: "string", Secret: true},
		}},
	}})
	require.NoError(t, err)

	srv := buildTestServerWithDBAndCatalog(t, db, cat)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/elasticsearch", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got outputConfigResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "elasticsearch", got.Name)
	assert.NotContains(t, got.Config, "password")
	assert.True(t, got.SecretFields["/password"])
	assert.Equal(t, "https://es:9200", got.Config["host"])
}

func TestHandlePipelineOutputByName_Miss(t *testing.T) {
	db := database.NewMemory()
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/absent", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 404, resp.StatusCode)
}

func TestHandlePipelineOutputByName_NoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/foo", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandlePipelineOutputByName_BackendFailureReturns500(t *testing.T) {
	srv := buildTestServerWithDB(t, allReadsFailDB())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/foo", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode, "backend read failure must surface as 500, not 404")
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "db failure")
}

func TestHandlePipelineOutputTypes(t *testing.T) {
	cat, err := catalog.New([]output.Type{
		{
			Name:     "slack",
			Category: "chat",
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: "slack"}, nil
			},
			Schema: output.Schema{Fields: []output.SchemaField{
				{Name: "secret_endpoint", Type: "string", Secret: true},
				{Name: "channel", Type: "string"},
			}},
		},
		{
			Name:     "webhook",
			Category: "webhook",
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: "webhook"}, nil
			},
			Schema: output.Schema{Fields: []output.SchemaField{
				{Name: "address", Type: "string", Required: true},
			}},
		},
	})
	require.NoError(t, err)

	srv := buildTestServerWithDBAndCatalog(t, database.NewMemory(), cat)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/types", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got struct {
		Types []output.Type `json:"types"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Types, 2)

	names := []string{got.Types[0].Name, got.Types[1].Name}
	assert.ElementsMatch(t, []string{"slack", "webhook"}, names)
}

func TestHandlePipelineOutputTypeByName_Hit(t *testing.T) {
	cat, err := catalog.New([]output.Type{{
		Name:     "slack",
		Category: "chat",
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "slack"}, nil
		},
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "secret_endpoint", Type: "string", Secret: true}}},
	}})
	require.NoError(t, err)

	srv := buildTestServerWithDBAndCatalog(t, database.NewMemory(), cat)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/types/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got output.Type
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "slack", got.Name)
	assert.Equal(t, "chat", got.Category)
	require.Len(t, got.Schema.Fields, 1)
	assert.True(t, got.Schema.Fields[0].Secret)
}

func TestHandlePipelineOutputTypeByName_Miss(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/types/absent", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 404, resp.StatusCode)
}

func TestHandlePipelineOutputsRouteOrdering_TypesWinsOverName(t *testing.T) {
	srv := buildTestServer(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/types", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode, "/api/v1/pipeline/outputs/types must resolve to the catalog handler, not the :name handler")

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"types"`)
}

func TestHandlePipelineLayout_NoLayout(t *testing.T) {
	db := database.NewMemory()
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/layout", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "{}", string(body))
}

func TestHandlePipelineLayout_Stored(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.SavePipelineLayout(t.Context(), &core.PipelineLayout{
		Nodes: []core.LayoutNode{{ID: "sidekick", X: 10, Y: 20}},
	}))
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/layout", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)
	var got core.PipelineLayout
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.Len(t, got.Nodes, 1)
	assert.Equal(t, "sidekick", got.Nodes[0].ID)
}

func TestHandlePipelineLayout_NoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/layout", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandlePipelineComposite(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack": {"host": "https://hooks.slack.com/x"},
		},
	}))
	require.NoError(t, db.SavePipelineLayout(t.Context(), &core.PipelineLayout{
		Nodes: []core.LayoutNode{{ID: "slack", X: 1, Y: 2}},
	}))

	cat, err := catalog.New([]output.Type{{
		Name: "slack",
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "slack"}, nil
		},
		Schema: output.Schema{Fields: []output.SchemaField{
			{Name: "host", Type: "string"},
		}},
	}})
	require.NoError(t, err)

	cfg := testutil.DefaultRuntimeConfig()
	out := pipeline.NewOutput(&testutil.MockDriver{DriverName: "slack"}, &cfg, nil)
	enricher, _ := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	dispatcher := pipeline.NewDispatcher([]*pipeline.Output{out})
	p, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)
	p.Start(context.Background(), func() {})

	srv, err := NewServer(&ServerConfig{
		Pipeline: p, Database: db, Catalog: cat,
	})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)

	var got struct {
		Outputs map[string]core.OutputConfigEntry `json:"outputs"`
		Layout  *core.PipelineLayout              `json:"layout"`
		Status  []pipeline.OutputStatus           `json:"status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))

	require.Contains(t, got.Outputs, "slack")
	assert.Equal(t, "https://hooks.slack.com/x", got.Outputs["slack"].Config["host"])

	require.Len(t, got.Status, 1)
	assert.Equal(t, "slack", got.Status[0].Name)

	require.NotNil(t, got.Layout)
	require.Len(t, got.Layout.Nodes, 1)
	assert.Equal(t, "slack", got.Layout.Nodes[0].ID)
}

func TestHandlePipelineComposite_NoDatabase(t *testing.T) {
	srv := buildTestServerWithDB(t, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 503, resp.StatusCode)
}

func TestHandlePipelineComposite_LayoutError(t *testing.T) {
	srv := buildTestServerWithDB(t, &databasetestutil.Mock{GetPipelineLayoutErr: errors.New("layout failed")})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "layout failed")
}

func TestHandleGetConfig_MaskingHelperWired(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Config: &core.Config{ListenAddress: "0.0.0.0", ListenPort: 2801, LogLevel: core.LogLevelInfo, LogFormat: core.LogFormatText},
	}))
	srv := buildTestServerWithDB(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/config", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode)

	var got core.ConfigEntry
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	require.NotNil(t, got.Config)
	assert.Equal(t, "0.0.0.0", got.Config.ListenAddress)
	assert.Equal(t, 2801, got.Config.ListenPort)
}

var _ = event.Event{}

func TestHandlePipelineOutputPut_CreatesNewUIOwned(t *testing.T) {
	db := database.NewMemory()
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"config":{"secret_endpoint":"https://hooks.slack.com/new"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	stored, err := db.GetOutputConfig(t.Context(), "slack")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.False(t, stored.Provisioned)
	assert.Equal(t, "https://hooks.slack.com/new", stored.Config["secret_endpoint"])
}

func TestHandlePipelineOutputPut_MergesAbsentKeys(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.SaveOutputConfig(context.Background(), "slack", map[string]any{
		"secret_endpoint": "https://hooks.slack.com/orig",
		"channel":         "#alerts",
	}))
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"config":{"channel":"#new"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	stored, err := db.GetOutputConfig(t.Context(), "slack")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "https://hooks.slack.com/orig", stored.Config["secret_endpoint"],
		"absent key must keep the existing secret_endpoint value")
	assert.Equal(t, "#new", stored.Config["channel"],
		"present key must overlay the existing value")
}

// nestedMutationCatalog has a Secret leaf at auth.password, like Kafka.
func nestedMutationCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.New([]output.Type{{
		Name: "kafka",
		Schema: output.Schema{
			Fields: []output.SchemaField{
				{Name: "topic", Type: "string", Required: true},
				{Name: "auth.sasl", Type: "string"},
				{Name: "auth.username", Type: "string"},
				{Name: "auth.password", Type: "string", Secret: true},
			},
		},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "kafka"}, nil
		},
	}})
	require.NoError(t, err)
	return cat
}

func TestHandlePipelineOutputPut_NestedPartialUpdatePreservesSiblings(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.SaveOutputConfig(context.Background(), "kafka", map[string]any{
		"topic": "falco-events",
		"auth": map[string]any{
			"sasl":     "plain",
			"username": "alice",
			"password": "hunter2",
		},
	}))
	rig := buildMutationRig(t, db, nestedMutationCatalog(t), true)

	body := bytes.NewReader([]byte(`{"config":{"auth":{"username":"bob"}}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/kafka", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	stored, err := db.GetOutputConfig(t.Context(), "kafka")
	require.NoError(t, err)
	require.NotNil(t, stored)
	auth, ok := stored.Config["auth"].(map[string]any)
	require.True(t, ok, "auth must remain a nested map after partial update")
	assert.Equal(t, "bob", auth["username"], "present nested key must overlay")
	assert.Equal(t, "plain", auth["sasl"], "absent nested sibling must be preserved")
	assert.Equal(t, "hunter2", auth["password"], "absent nested secret must be preserved")
	assert.Equal(t, "falco-events", stored.Config["topic"], "top-level sibling must be preserved")
}

func TestHandlePipelineOutputPut_NestedSecretPlaceholderRejected(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.SaveOutputConfig(context.Background(), "kafka", map[string]any{
		"topic": "falco-events",
		"auth": map[string]any{
			"username": "alice",
			"password": "hunter2",
		},
	}))
	rig := buildMutationRig(t, db, nestedMutationCatalog(t), true)

	body := bytes.NewReader([]byte(`{"config":{"auth":{"password":"****"}}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/kafka", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "auth.password")
	assert.Contains(t, string(respBody), "secret placeholder")

	stored, err := db.GetOutputConfig(t.Context(), "kafka")
	require.NoError(t, err)
	require.NotNil(t, stored)
	auth := stored.Config["auth"].(map[string]any)
	assert.Equal(t, "hunter2", auth["password"], "rejection must not persist the sentinel")
}

func TestHandlePipelineOutputs_NestedSecretMaskedInGet(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(t.Context(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"kafka": {
				"topic": "falco-events",
				"auth": map[string]any{
					"sasl":     "plain",
					"username": "alice",
					"password": "real-password",
				},
			},
		},
	}))
	cat := nestedMutationCatalog(t)
	srv := buildTestServerWithDBAndCatalog(t, db, cat)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/pipeline/outputs/kafka", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got core.OutputConfigEntry
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	auth := got.Config["auth"].(map[string]any)
	assert.NotContains(t, auth, "password")
	assert.Equal(t, "plain", auth["sasl"], "non-secret sibling must pass through")
	assert.Equal(t, "alice", auth["username"])
}

func TestHandlePipelineOutputPut_RejectsSecretPlaceholder(t *testing.T) {
	db := database.NewMemory()
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"config":{"secret_endpoint":"****"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "secret placeholder")

	stored, err := db.GetOutputConfig(t.Context(), "slack")
	require.NoError(t, err)
	assert.Nil(t, stored, "rejection must not persist anything to the DB")
}

func TestHandlePipelineOutputPut_UnknownTypeRejected(t *testing.T) {
	db := database.NewMemory()
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"config":{}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/not-a-type", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "unknown output type")

	stored, err := db.GetOutputConfig(t.Context(), "not-a-type")
	require.NoError(t, err)
	assert.Nil(t, stored)
}

func TestHandlePipelineOutputPut_RejectedConfigNeverEchoesValues(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)

	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "malformed url", body: `{"config":{"host":"https://u:` + sentinel + `@ho st/x"}}`, want: "host: invalid URL"},
		{name: "unsupported scheme", body: `{"config":{"host":"ftp://u:` + sentinel + `@host/x"}}`, want: "host: scheme must be http or https"},
		{name: "wrong secret type", body: `{"config":{"host":"https://h","password":{"a":"` + sentinel + `"}}}`, want: "password: invalid type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rig := buildMutationRig(t, database.NewMemory(), cat, true)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/webhook", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			resp, err := rig.Server.app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			respBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Contains(t, string(respBody), tc.want)
			assert.NotContains(t, string(respBody), sentinel)
		})
	}
}

func TestHandlePipelineOutputPut_SecretFileFailureReturns500(t *testing.T) {
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	rig := buildMutationRig(t, database.NewMemory(), cat, true)

	body := bytes.NewReader([]byte(`{"config":{"host":"https://h","password_file":"/nonexistent/secret"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/webhook", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHandlePipelineOutputPut_InvalidBodyNeverEchoesValues(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	for name, body := range map[string]string{
		"scalar config": `{"config":"` + sentinel + `"}`,
		"truncated":     `{"config":{"password":"` + sentinel,
	} {
		t.Run(name, func(t *testing.T) {
			srv := buildMutationTestServer(t, database.NewMemory())
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", bytes.NewReader([]byte(body)))
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			respBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.NotContains(t, string(respBody), "s3cret")
		})
	}
}

func TestHandlePipelineOutputPut_BadJSONReturns400(t *testing.T) {
	db := database.NewMemory()
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{not json`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandlePipelineOutputPut_NoReloaderReturns503(t *testing.T) {
	db := database.NewMemory()
	srv := buildMutationTestServerNilReloader(t, db)

	body := bytes.NewReader([]byte(`{"config":{}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandlePipelineOutputDelete_Success(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.SaveOutputConfig(context.Background(), "slack", map[string]any{"secret_endpoint": "x"}))
	srv := buildMutationTestServer(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	stored, err := db.GetOutputConfig(t.Context(), "slack")
	require.NoError(t, err)
	assert.Nil(t, stored, "delete must remove the entry from the DB")
}

func TestHandlePipelineOutputDelete_NotFound(t *testing.T) {
	db := database.NewMemory()
	srv := buildMutationTestServer(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandlePipelineOutputPut_ProvisionedReturns409WhenUpdatesDisabled(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(context.Background(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{"slack": {"secret_endpoint": "file"}},
	}))
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"config":{"secret_endpoint":"ui"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusConflict, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "provisioning.allow_ui_updates")

	stored, err := db.GetOutputConfig(t.Context(), "slack")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "file", stored.Config["secret_endpoint"],
		"rejected PUT must not mutate the stored entry")
}

func TestHandlePipelineOutputPut_ProvisionedSucceedsWhenUpdatesAllowed(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(context.Background(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{"slack": {"secret_endpoint": "file"}},
	}))
	rig := buildMutationRigWithProvisioning(t, db, newMutationTestCatalog(t), core.ProvisioningConfig{AllowUIUpdates: true})

	body := bytes.NewReader([]byte(`{"config":{"secret_endpoint":"ui-edit"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	stored, err := db.GetOutputConfig(t.Context(), "slack")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.Provisioned, "UI edit of a provisioned entry keeps Provisioned:true")
	assert.Equal(t, "ui-edit", stored.Config["secret_endpoint"])
}

func TestHandlePipelineOutputDelete_ProvisionedReturns409WhenUpdatesDisabled(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(context.Background(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{"slack": {"secret_endpoint": "file"}},
	}))
	srv := buildMutationTestServer(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusConflict, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "provisioning.allow_ui_updates")

	stored, err := db.GetOutputConfig(t.Context(), "slack")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.Provisioned, "entry must be unchanged after 409")
}

func TestHandlePipelineOutputDelete_ProvisionedSucceedsWhenUpdatesAllowed(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.Provision(context.Background(), &core.ProvisionRequest{
		Outputs: map[string]map[string]any{"slack": {"secret_endpoint": "file"}},
	}))
	rig := buildMutationRigWithProvisioning(t, db, newMutationTestCatalog(t), core.ProvisioningConfig{AllowUIUpdates: true})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	stored, err := db.GetOutputConfig(t.Context(), "slack")
	require.NoError(t, err)
	assert.Nil(t, stored, "DELETE must clear the DB entry when allow_ui_updates=true")
}

func TestHandlePipelineLayoutPut_Success(t *testing.T) {
	db := database.NewMemory()
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"nodes":[{"id":"slack","x":100,"y":200}]}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/layout", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	stored, err := db.GetPipelineLayout(t.Context())
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Len(t, stored.Nodes, 1)
	assert.Equal(t, "slack", stored.Nodes[0].ID)
	assert.Equal(t, float64(100), stored.Nodes[0].X)
	assert.Equal(t, float64(200), stored.Nodes[0].Y)
}

func TestHandlePipelineLayoutPut_BadJSON(t *testing.T) {
	db := database.NewMemory()
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`not-json`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/layout", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestHandlePipelineLayoutPut_NoDatabase(t *testing.T) {
	srv := buildMutationTestServer(t, nil)

	body := bytes.NewReader([]byte(`{"nodes":[]}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/layout", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandlePipelineOutputPut_DBReadErrorReturns500(t *testing.T) {
	db := &databasetestutil.Mock{GetOutputConfigErr: errors.New("db read boom")}
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"config":{}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHandlePipelineOutputPut_DispatcherStoppedReturns503(t *testing.T) {
	db := database.NewMemory()
	rig := buildMutationRig(t, db, newMutationTestCatalog(t), true)
	// Shut the dispatcher down so the Reloader's next Add/Replace returns ErrDispatcherStopped.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, rig.Dispatcher.Shutdown(shutdownCtx, func() {}))

	body := bytes.NewReader([]byte(`{"config":{"secret_endpoint":"x"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandlePipelineOutputPut_ReloaderNotBoundReturns503(t *testing.T) {
	db := database.NewMemory()
	// bindReloader=false exercises the unbound-Reloader path.
	rig := buildMutationRig(t, db, newMutationTestCatalog(t), false)

	body := bytes.NewReader([]byte(`{"config":{"secret_endpoint":"x"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandlePipelineOutputPut_DBSaveErrorReturns500(t *testing.T) {
	db := &databasetestutil.Mock{SaveOutputConfigErr: errors.New("db save boom")}
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"config":{"secret_endpoint":"x"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "database save failed",
		"error body must surface the ErrDBSyncFailed partial-state warning")
}

func TestHandlePipelineOutputPut_EmptyName(t *testing.T) {
	db := database.NewMemory()
	srv := buildMutationTestServer(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/", bytes.NewReader([]byte(`{"config":{}}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

func TestHandlePipelineOutputDelete_NoReloaderReturns503(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.SaveOutputConfig(context.Background(), "slack", map[string]any{"secret_endpoint": "x"}))
	srv := buildMutationTestServerNilReloader(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandlePipelineOutputDelete_DBReadErrorReturns500(t *testing.T) {
	db := &databasetestutil.Mock{GetOutputConfigErr: errors.New("db read boom")}
	srv := buildMutationTestServer(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHandlePipelineOutputDelete_DispatcherStoppedReturns503(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.SaveOutputConfig(context.Background(), "slack", map[string]any{"secret_endpoint": "x"}))
	rig := buildMutationRig(t, db, newMutationTestCatalog(t), true)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, rig.Dispatcher.Shutdown(shutdownCtx, func() {}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandlePipelineOutputDelete_DBDeleteErrorReturns500(t *testing.T) {
	db := &databasetestutil.Mock{
		Outputs: map[string]*core.OutputConfigEntry{
			"slack": {Name: "slack", Config: map[string]any{"secret_endpoint": "x"}},
		},
		DeleteOutputConfigErr: errors.New("db delete boom"),
	}
	srv := buildMutationTestServer(t, db)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "database delete failed")
}

func TestHandlePipelineLayoutPut_SaveErrorReturns500(t *testing.T) {
	db := &databasetestutil.Mock{SavePipelineLayoutErr: errors.New("db save layout boom")}
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"nodes":[]}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/layout", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHandlePipelineLayoutPut_RereadErrorReturns500(t *testing.T) {
	db := &databasetestutil.Mock{GetPipelineLayoutErr: errors.New("db reread layout boom")}
	srv := buildMutationTestServer(t, db)

	body := bytes.NewReader([]byte(`{"nodes":[{"id":"x","x":1,"y":2}]}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/layout", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestContainsSecretPlaceholder_NoSchemaFallback(t *testing.T) {
	cfg := map[string]any{"anything": "****"}
	field := containsSecretPlaceholder(cfg, output.Type{})
	assert.Equal(t, "anything", field, "no-schema fallback must flag any string value equal to the sentinel")
}

func TestContainsSecretPlaceholder_NilConfig(t *testing.T) {
	field := containsSecretPlaceholder(nil, output.Type{Name: "slack"})
	assert.Equal(t, "", field, "nil config must not trigger rejection")
}

func TestContainsSecretPlaceholder_NonSecretFieldWithSentinelValueAllowed(t *testing.T) {
	cfg := map[string]any{"channel": "****"}
	t2 := output.Type{
		Name: "slack",
		Schema: output.Schema{Fields: []output.SchemaField{
			{Name: "secret_endpoint", Secret: true},
			{Name: "channel"},
		}},
	}
	field := containsSecretPlaceholder(cfg, t2)
	assert.Equal(t, "", field, "non-secret field with sentinel value must not trigger rejection")
}

func TestMergeOutputConfig_NilExisting(t *testing.T) {
	merged := mergeOutputConfig(nil, map[string]any{"a": 1})
	assert.Equal(t, map[string]any{"a": 1}, merged)
}

func TestHandlePipelineOutputPut_NoDatabaseReturns503(t *testing.T) {
	srv := buildMutationTestServer(t, nil)
	body := bytes.NewReader([]byte(`{"config":{}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandlePipelineOutputDelete_NoDatabaseReturns503(t *testing.T) {
	srv := buildMutationTestServer(t, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := srv.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestHandlePipelineOutputPut_ApplyInitFailureReturns500(t *testing.T) {
	db := database.NewMemory()
	// A driver that fails Init makes the real Reloader return an apply error.
	cat, err := catalog.New([]output.Type{{
		Name:   "slack",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "secret_endpoint", Type: "string", Required: true, Secret: true}}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{
				DriverName: "slack",
				InitFunc: func(_ context.Context) error {
					return errors.New("init failed by test driver")
				},
			}, nil
		},
	}})
	require.NoError(t, err)
	rig := buildMutationRig(t, db, cat, true)

	body := bytes.NewReader([]byte(`{"config":{"secret_endpoint":"x"}}`))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/v1/pipeline/outputs/slack", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(respBody), "apply init",
		"init failure from the real Reloader must surface under the default 500 mapping")
}

func TestHandlePipelineOutputDelete_ReloaderNotBoundReturns503(t *testing.T) {
	db := database.NewMemory()
	require.NoError(t, db.SaveOutputConfig(context.Background(), "slack", map[string]any{"secret_endpoint": "x"}))
	rig := buildMutationRig(t, db, newMutationTestCatalog(t), false)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/pipeline/outputs/slack", http.NoBody)
	resp, err := rig.Server.app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
