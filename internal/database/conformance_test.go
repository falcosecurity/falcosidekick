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

package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

// postgresDSNEnv names the postgres the conformance suite runs on; without it the postgres run is
// skipped, unless postgresRequiredEnv is set, as in CI, where a skip would hide the missing database.
const (
	postgresDSNEnv      = "FALCOSIDEKICK_E2E_POSTGRES_DSN"
	postgresRequiredEnv = "FALCOSIDEKICK_E2E_POSTGRES_REQUIRED"
)

type openStore func(t *testing.T) core.Database

func TestMemoryConformance(t *testing.T) {
	runConformance(t, func(*testing.T) core.Database { return NewMemory() })
}

func TestSQLiteConformance(t *testing.T) {
	runConformance(t, func(t *testing.T) core.Database {
		s, err := OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "sidekick.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}

func TestPostgresConformance(t *testing.T) {
	runConformance(t, openPostgresSchema)
}

// postgresConfig returns the settings of the test postgres with search_path set to schema, if any.
func postgresConfig(t *testing.T, schema string) *pgx.ConnConfig {
	t.Helper()
	dsn := os.Getenv(postgresDSNEnv)
	if dsn == "" {
		if os.Getenv(postgresRequiredEnv) != "" {
			t.Fatal(postgresDSNEnv + " is not set")
		}
		t.Skip(postgresDSNEnv + " is not set")
	}
	cfg, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	if schema != "" {
		cfg.RuntimeParams["search_path"] = schema
	}
	return cfg
}

// openPostgresSchema opens the store in a new schema of the test postgres, so every test starts empty.
func openPostgresSchema(t *testing.T) core.Database {
	t.Helper()
	s, err := OpenPostgres(t.Context(), postgresConfig(t, newPostgresSchema(t)), 4)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// newPostgresSchema creates an empty schema, dropped at the end of the test.
func newPostgresSchema(t *testing.T) string {
	t.Helper()
	suffix := make([]byte, 6)
	_, err := rand.Read(suffix)
	require.NoError(t, err)
	schema := "fsk_" + hex.EncodeToString(suffix)
	admin := stdlib.OpenDB(*postgresConfig(t, ""))
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	})
	_, err = admin.ExecContext(t.Context(), "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	return schema
}

func runConformance(t *testing.T, open openStore) {
	t.Run("conditional writes", func(t *testing.T) {
		s, ctx := open(t), t.Context()

		_, err := s.SaveOutputConfig(ctx, "slack", 3, map[string]any{"v": 0})
		require.ErrorIs(t, err, core.ErrVersionConflict, "an update of a missing output")
		first, err := s.SaveOutputConfig(ctx, "slack", 0, map[string]any{"v": 1})
		require.NoError(t, err)
		_, err = s.SaveOutputConfig(ctx, "slack", 0, map[string]any{"v": "again"})
		require.ErrorIs(t, err, core.ErrVersionConflict, "a second create")
		second, err := s.SaveOutputConfig(ctx, "slack", first, map[string]any{"v": 2})
		require.NoError(t, err)
		assert.Greater(t, second, first)
		_, err = s.SaveOutputConfig(ctx, "slack", first, map[string]any{"v": "stale"})
		require.ErrorIs(t, err, core.ErrVersionConflict)

		require.ErrorIs(t, s.DeleteOutputConfig(ctx, "slack", 0), core.ErrVersionConflict, "it exists")
		require.ErrorIs(t, s.DeleteOutputConfig(ctx, "slack", first), core.ErrVersionConflict)
		require.NoError(t, s.DeleteOutputConfig(ctx, "slack", second))
		require.ErrorIs(t, s.DeleteOutputConfig(ctx, "slack", second), core.ErrVersionConflict, "already deleted")
		require.NoError(t, s.DeleteOutputConfig(ctx, "slack", 0), "deleting a missing output at version 0")

		entry, err := s.GetOutputConfig(ctx, "slack")
		require.NoError(t, err)
		assert.Nil(t, entry)
	})

	t.Run("versions are never reused", func(t *testing.T) {
		s, ctx := open(t), t.Context()
		first, err := s.SaveOutputConfig(ctx, "slack", 0, map[string]any{"v": 1})
		require.NoError(t, err)
		require.NoError(t, s.DeleteOutputConfig(ctx, "slack", first))
		again, err := s.SaveOutputConfig(ctx, "slack", 0, map[string]any{"v": 2})
		require.NoError(t, err)
		require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{Outputs: map[string]map[string]any{"loki": {"host": "h"}}}))
		loki, err := s.GetOutputConfig(ctx, "loki")
		require.NoError(t, err)
		assert.Greater(t, again, first)
		assert.Greater(t, loki.Version, again)
	})

	t.Run("read back", func(t *testing.T) {
		s, ctx := open(t), t.Context()
		cfg := map[string]any{
			"host":    "https://h",
			"port":    5,
			"big":     int64(1<<60 + 1),
			"ratio":   1.5,
			"enabled": true,
			"tags":    []any{"a", "b"},
			"headers": map[string]any{"X-Key": map[string]any{"files": []any{"/run/secrets/k"}}},
		}
		version, err := s.SaveOutputConfig(ctx, "webhook", 0, cfg)
		require.NoError(t, err)

		entry, err := s.GetOutputConfig(ctx, "webhook")
		require.NoError(t, err)
		require.NotNil(t, entry)
		assert.Equal(t, "webhook", entry.Name)
		assert.Equal(t, version, entry.Version)
		assert.False(t, entry.Provisioned)
		assert.False(t, entry.UpdatedAt.IsZero())
		assert.True(t, sameConfig(cfg, entry.Config), "%v read back as %v", cfg, entry.Config)
		assert.Equal(t, int64(1<<60+1), entry.Config["big"], "integers keep their precision")

		all, err := s.GetOutputConfigs(ctx)
		require.NoError(t, err)
		assert.Equal(t, []string{"webhook"}, keys(all))

		entry.Config["host"] = "changed by the caller"
		again, err := s.GetOutputConfig(ctx, "webhook")
		require.NoError(t, err)
		assert.Equal(t, "https://h", again.Config["host"], "a read is a copy")

		missing, err := s.GetOutputConfig(ctx, "missing")
		require.NoError(t, err)
		assert.Nil(t, missing)
	})

	t.Run("provisioning", func(t *testing.T) {
		s, ctx := open(t), t.Context()
		apiVersion, err := s.SaveOutputConfig(ctx, "webhook", 0, map[string]any{"host": "from-api"})
		require.NoError(t, err)
		_, err = s.SaveOutputConfig(ctx, "slack", 0, map[string]any{"channel": "from-api"})
		require.NoError(t, err)

		require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{Outputs: map[string]map[string]any{
			"loki":  {"host": "https://loki", "port": 3100, "big": int64(1<<60 + 1)},
			"slack": {"channel": "from-file"},
		}}))
		loki, err := s.GetOutputConfig(ctx, "loki")
		require.NoError(t, err)
		slack, err := s.GetOutputConfig(ctx, "slack")
		require.NoError(t, err)
		assert.True(t, loki.Provisioned)
		assert.True(t, slack.Provisioned, "the files win a name stored through the API")
		assert.Equal(t, "from-file", slack.Config["channel"])

		require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{Outputs: map[string]map[string]any{
			"loki":  {"host": "https://loki", "port": 3100, "big": int64(1<<60 + 1)},
			"slack": {"channel": "changed"},
		}}))
		lokiAgain, err := s.GetOutputConfig(ctx, "loki")
		require.NoError(t, err)
		assert.Equal(t, loki.Version, lokiAgain.Version, "an unchanged output keeps its version after a read back")
		slackAgain, err := s.GetOutputConfig(ctx, "slack")
		require.NoError(t, err)
		assert.Greater(t, slackAgain.Version, slack.Version)

		require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{Outputs: map[string]map[string]any{}}))
		all, err := s.GetOutputConfigs(ctx)
		require.NoError(t, err)
		assert.Equal(t, []string{"webhook"}, keys(all), "provisioned outputs missing from the files are deleted, API ones kept")
		assert.Equal(t, apiVersion, all["webhook"].Version)

		require.Error(t, s.Provision(ctx, nil))
	})

	t.Run("an API write keeps the provisioned flag", func(t *testing.T) {
		s, ctx := open(t), t.Context()
		require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{Outputs: map[string]map[string]any{"loki": {"host": "a"}}}))
		loki, err := s.GetOutputConfig(ctx, "loki")
		require.NoError(t, err)
		_, err = s.SaveOutputConfig(ctx, "loki", loki.Version, map[string]any{"host": "b"})
		require.NoError(t, err)
		edited, err := s.GetOutputConfig(ctx, "loki")
		require.NoError(t, err)
		assert.True(t, edited.Provisioned)
		assert.Equal(t, "b", edited.Config["host"])
	})

	t.Run("layout", func(t *testing.T) {
		s, ctx := open(t), t.Context()
		layout, err := s.GetPipelineLayout(ctx)
		require.NoError(t, err)
		assert.Nil(t, layout)

		require.NoError(t, s.SavePipelineLayout(ctx, &core.PipelineLayout{Nodes: []core.LayoutNode{{ID: "a", X: 1.5, Y: 2}}}))
		require.NoError(t, s.SavePipelineLayout(ctx, &core.PipelineLayout{Nodes: []core.LayoutNode{{ID: "b", X: 3, Y: 4}}}))
		layout, err = s.GetPipelineLayout(ctx)
		require.NoError(t, err)
		require.NotNil(t, layout)
		assert.Equal(t, []core.LayoutNode{{ID: "b", X: 3, Y: 4}}, layout.Nodes)
		assert.False(t, layout.UpdatedAt.IsZero())
	})
}

func keys(m map[string]*core.OutputConfigEntry) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}
