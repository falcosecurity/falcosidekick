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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

func readOnlyServer(t *testing.T, rig *mutationTestRig) *Server {
	t.Helper()
	srv, err := NewServer(&ServerConfig{
		Pipeline: rig.Server.pipeline,
		Database: rig.Server.database,
		Catalog:  rig.Server.catalog,
		Reloader: rig.Reloader,
		Config:   &core.Config{},
	})
	require.NoError(t, err)
	return srv
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func TestEveryWriteRouteIsForbiddenByDefault(t *testing.T) {
	db := database.NewMemory()
	rig := buildMutationRig(t, db, newMutationTestCatalog(t), true)
	srv := readOnlyServer(t, rig)

	var checked int
	for _, route := range srv.app.GetRoutes(true) {
		if !isWriteMethod(route.Method) || (route.Method == http.MethodPost && route.Path == "/") {
			continue
		}
		path := strings.ReplaceAll(route.Path, ":name", "webhook")
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), route.Method, path,
				bytes.NewReader([]byte(`{"type":"webhook","config":{"host":"http://127.0.0.1:1"}}`)))
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.app.Test(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			body, _ := io.ReadAll(resp.Body)
			var decoded map[string]string
			require.NoError(t, json.Unmarshal(body, &decoded))
			assert.Equal(t, errWritesDisabled, decoded["error"])
		})
		checked++
	}
	assert.Equal(t, 3, checked, "known write routes: PUT layout, PUT output, DELETE output")

	entries, err := db.GetOutputConfigs(context.Background())
	require.NoError(t, err)
	assert.Empty(t, entries, "a forbidden write must not reach the database")
}

func TestIngestionIsNotAWrite(t *testing.T) {
	rig := buildMutationRig(t, database.NewMemory(), newMutationTestCatalog(t), true)
	srv := readOnlyServer(t, rig)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/",
		bytes.NewReader([]byte(`{"rule":"r","time":"2026-11-05T10:00:00Z","priority":"Warning","output_fields":{"a":"b"}}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.ingestion.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestWritesWarningOnlyOffLoopback(t *testing.T) {
	for _, tc := range []struct {
		address     string
		allowWrites bool
		warn        bool
	}{
		{address: "0.0.0.0", allowWrites: true, warn: true},
		{address: "", allowWrites: true, warn: true},
		{address: "10.0.0.5", allowWrites: true, warn: true},
		{address: "127.0.0.1", allowWrites: true},
		{address: "::1", allowWrites: true},
		{address: "localhost", allowWrites: true},
		{address: "0.0.0.0"},
	} {
		t.Run(tc.address, func(t *testing.T) {
			var logs bytes.Buffer
			rig := buildMutationRig(t, database.NewMemory(), newMutationTestCatalog(t), true)
			cfg := testConfig(t)
			cfg.Management.ListenAddress = tc.address
			cfg.API.AllowWrites = tc.allowWrites
			_, err := NewServer(&ServerConfig{
				Pipeline: rig.Server.pipeline,
				Catalog:  rig.Server.catalog,
				Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
				Config:   cfg,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.warn, strings.Contains(logs.String(), "API writes are enabled without authentication"))
		})
	}
}
