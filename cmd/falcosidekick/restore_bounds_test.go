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

package main

import (
	"context"
	"maps"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/outputs/inmemory"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

// A row written before the bounds fails before anything is allocated; the others start.
func TestRestoreFromDB_OutputsOutOfBoundsStartFailed(t *testing.T) {
	ctx := context.Background()
	cfg := loadDefaultConfigForCmdTest(t)
	mock := func(name string) output.Type {
		return output.Type{
			Name:   name,
			Schema: output.Schema{Fields: shared.RuntimeConfigSchemaFields()},
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: name}, nil
			},
		}
	}
	teams := mock("teams")
	teams.New = func(raw map[string]any, _ output.Deps) (output.Driver, error) {
		var cfg struct {
			Runtime output.RuntimeConfig `mapstructure:"runtime"`
		}
		if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
			return nil, err
		}
		return &testutil.MockDriver{DriverName: "teams"}, nil
	}
	discord := mock("discord")
	discord.New = teams.New
	cat, err := catalog.New([]output.Type{inmemory.OutputType, mock("webhook"), mock("slack"), mock("loki"), teams, discord})
	require.NoError(t, err)
	db, err := database.OpenSQLite(ctx, filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	for name, c := range map[string]map[string]any{
		"inmemory": {"capacity": 1e9},
		"webhook":  {"runtime": map[string]any{"workers": 1e20}},
		"slack":    {"runtime": map[string]any{"queue_size": 1.9}},
		"loki":     {"runtime": map[string]any{"workers": 4, "health_check": false, "queue_size": nil}},
		"teams":    {"typo": nil},
		"discord":  {"runtime": map[string]any{"health_check": 2}},
	} {
		_, err := db.SaveOutputConfig(ctx, name, 0, c)
		require.NoError(t, err)
	}

	restored, err := restoreFromDB(ctx, cfg, db, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), nil)
	require.NoError(t, err)
	require.Len(t, restored.outputs, 1)
	t.Cleanup(func() { _ = restored.outputs[0].Close() })
	assert.Equal(t, "loki", restored.outputs[0].Name())
	assert.ElementsMatch(t, []string{"inmemory", "webhook", "slack", "teams", "discord"}, slices.Collect(maps.Keys(restored.failures)))
	assert.ErrorContains(t, restored.failures["teams"], "unknown keys: typo", "a null under an unknown key is refused at restore")
	assert.ErrorContains(t, restored.failures["discord"], "runtime.health_check: must be true or false",
		"a number stored for a boolean is refused at restore")
	assert.ErrorContains(t, restored.failures["inmemory"], "capacity: must be an integer between 1 and 100000")
	assert.ErrorContains(t, restored.failures["webhook"], "runtime.workers: is out of range")
	assert.ErrorContains(t, restored.failures["slack"], "runtime.queue_size: must be an integer")
}

// The integer 0, a json.Number from the store, is "0s": a row starts or fails at restore as it was accepted or refused.
func TestRestoreFromDB_ZeroDurationsReadAsWritten(t *testing.T) {
	ctx := context.Background()
	cfg := loadDefaultConfigForCmdTest(t)
	runtimeType := func(name string) output.Type {
		return output.Type{
			Name:   name,
			Schema: output.Schema{Fields: shared.BatchRuntimeConfigSchemaFields()},
			New: func(raw map[string]any, _ output.Deps) (output.Driver, error) {
				var cfg struct {
					Runtime output.RuntimeConfig `mapstructure:"runtime"`
				}
				if err := shared.DecodeDriverConfig(raw, &cfg); err != nil {
					return nil, err
				}
				return &testutil.MockDriver{DriverName: name}, nil
			},
		}
	}
	cat, err := catalog.New([]output.Type{inmemory.OutputType, runtimeType("webhook"), runtimeType("slack"), runtimeType("loki"), runtimeType("teams")})
	require.NoError(t, err)
	db, err := database.OpenSQLite(ctx, filepath.Join(t.TempDir(), "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	for name, c := range map[string]map[string]any{
		"inmemory": {"capacity": 10, "ttl": 0},
		"webhook":  {"runtime": map[string]any{"retry": map[string]any{"initial_interval": 0}}},
		"slack":    {"runtime": map[string]any{"retry": map[string]any{"max_interval": "0s"}}},
		"loki":     {"runtime": map[string]any{"circuit_breaker": map[string]any{"reset_timeout": 0}}},
		"teams":    {"runtime": map[string]any{"batching": map[string]any{"flush_interval": 0}}},
	} {
		_, err := db.SaveOutputConfig(ctx, name, 0, c)
		require.NoError(t, err)
	}

	restored, err := restoreFromDB(ctx, cfg, db, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), nil)
	require.NoError(t, err)
	require.Len(t, restored.outputs, 1)
	t.Cleanup(func() { _ = restored.outputs[0].Close() })
	assert.Equal(t, "inmemory", restored.outputs[0].Name())
	assert.ElementsMatch(t, []string{"webhook", "slack", "loki", "teams"}, slices.Collect(maps.Keys(restored.failures)))
	assert.ErrorContains(t, restored.failures["webhook"], "runtime.retry.initial_interval: must be a duration between 1ms and 1h")
	assert.ErrorContains(t, restored.failures["slack"], "runtime.retry.max_interval: must be a duration between 1ms and 1h")
	assert.ErrorContains(t, restored.failures["loki"], "runtime.circuit_breaker.reset_timeout: must be a duration between 1s and 1h")
	assert.ErrorContains(t, restored.failures["teams"], "runtime.batching.flush_interval: must be a duration between 10ms and 1h")
}
