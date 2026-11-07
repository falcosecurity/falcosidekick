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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

func TestImplementsDatabase(t *testing.T) {
	var _ core.Database = NewMemory()
}

// saveOutput writes cfg over whatever version is stored.
func saveOutput(t *testing.T, s *Memory, name string, cfg map[string]any) int64 {
	t.Helper()
	entry, err := s.GetOutputConfig(context.Background(), name)
	require.NoError(t, err)
	version, err := s.SaveOutputConfig(context.Background(), name, storedVersion(entry), cfg)
	require.NoError(t, err)
	return version
}

func TestOutputWritesAreConditional(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	_, err := s.SaveOutputConfig(ctx, "slack", 3, map[string]any{"v": 0})
	require.ErrorIs(t, err, core.ErrVersionConflict, "a create expects version 0")
	first, err := s.SaveOutputConfig(ctx, "slack", 0, map[string]any{"v": 1})
	require.NoError(t, err)
	_, err = s.SaveOutputConfig(ctx, "slack", 0, map[string]any{"v": "again"})
	require.ErrorIs(t, err, core.ErrVersionConflict, "a second create is refused")
	second, err := s.SaveOutputConfig(ctx, "slack", first, map[string]any{"v": 2})
	require.NoError(t, err)
	assert.Greater(t, second, first)
	_, err = s.SaveOutputConfig(ctx, "slack", first, map[string]any{"v": "stale"})
	require.ErrorIs(t, err, core.ErrVersionConflict)

	require.ErrorIs(t, s.DeleteOutputConfig(ctx, "slack", first), core.ErrVersionConflict)
	require.NoError(t, s.DeleteOutputConfig(ctx, "slack", second))
	require.ErrorIs(t, s.DeleteOutputConfig(ctx, "slack", second), core.ErrVersionConflict, "already deleted")

	entry, err := s.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	assert.Nil(t, entry)
}

func TestProvisionCreatesEntries(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	err := s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack":  {"secret_endpoint": "https://hooks.slack.com/test"},
			"memory": {"capacity": 5000},
		},
	})
	require.NoError(t, err)

	entries, err := s.GetOutputConfigs(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.True(t, entries["slack"].Provisioned)
	assert.True(t, entries["memory"].Provisioned)
	assert.Equal(t, "https://hooks.slack.com/test", entries["slack"].Config["secret_endpoint"])
}

func TestProvisionOverwritesProvisioned(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack": {"secret_endpoint": "old"},
		},
	}))

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack": {"secret_endpoint": "new"},
		},
	}))

	entry, err := s.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	assert.Equal(t, "new", entry.Config["secret_endpoint"])
}

func TestProvisionRemovesStaleProvisioned(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack": {"secret_endpoint": "host"},
			"loki":  {"hostport": "http://loki:3100"},
		},
	}))

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack": {"secret_endpoint": "host"},
		},
	}))

	entries, err := s.GetOutputConfigs(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Contains(t, entries, "slack")
}

func TestProvisionPreservesUICreatedEntries(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	saveOutput(t, s, "custom", map[string]any{"host": "http://custom"})

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack": {"secret_endpoint": "host"},
		},
	}))

	entries, err := s.GetOutputConfigs(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.False(t, entries["custom"].Provisioned, "UI-created entry must not be marked provisioned")
	assert.True(t, entries["slack"].Provisioned)
}

func TestProvisionNilRequest(t *testing.T) {
	s := NewMemory()
	err := s.Provision(context.Background(), nil)
	assert.Error(t, err)
}

func TestGetOutputConfigMissReturnsNilNil(t *testing.T) {
	s := NewMemory()
	entry, err := s.GetOutputConfig(context.Background(), "nonexistent")
	require.NoError(t, err, "miss must not be represented as an error")
	assert.Nil(t, entry, "miss must return a nil entry")
}

func TestSaveOutputConfigNotProvisioned(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	saveOutput(t, s, "custom", map[string]any{"host": "http://example.com"})

	entry, err := s.GetOutputConfig(ctx, "custom")
	require.NoError(t, err)
	assert.False(t, entry.Provisioned)
	assert.Equal(t, "http://example.com", entry.Config["host"])
	assert.False(t, entry.UpdatedAt.IsZero())
}

func TestDeleteOutputConfig(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	version := saveOutput(t, s, "temp", map[string]any{"x": 1})
	require.NoError(t, s.DeleteOutputConfig(ctx, "temp", version))

	entry, err := s.GetOutputConfig(ctx, "temp")
	require.NoError(t, err, "after delete, lookup miss must not be an error")
	assert.Nil(t, entry, "after delete, lookup must return a nil entry")
}

func TestDeleteOutputConfigMissReturnsNil(t *testing.T) {
	s := NewMemory()
	err := s.DeleteOutputConfig(context.Background(), "nonexistent", 0)
	require.NoError(t, err, "deleting a missing entry at version 0 is a no-op")
}

func TestProvisionOverwritesUIEditedProvisionedEntry(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{"slack": {"secret_endpoint": "file-v1"}},
	}))
	saveOutput(t, s, "slack", map[string]any{"secret_endpoint": "ui-edit"})
	after, err := s.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	require.NotNil(t, after)
	require.True(t, after.Provisioned,
		"SaveOutputConfig must preserve the Provisioned flag on an existing file-provisioned entry")
	require.Equal(t, "ui-edit", after.Config["secret_endpoint"])

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{"slack": {"secret_endpoint": "file-v2"}},
	}))
	got, err := s.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Provisioned, "still provisioned after reload")
	assert.Equal(t, "file-v2", got.Config["secret_endpoint"],
		"file reload must overwrite the UI edit with the file version")
}

func TestProvisionDisableDeletionKeepsOrphanProvisioned(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack":   {"host": "slack-file"},
			"webhook": {"host": "webhook-file"},
		},
	}))

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs:         map[string]map[string]any{"slack": {"host": "slack-file"}},
		DisableDeletion: true,
	}))

	orphan, err := s.GetOutputConfig(ctx, "webhook")
	require.NoError(t, err)
	require.NotNil(t, orphan, "DisableDeletion=true must preserve the orphaned Provisioned:true entry")
	assert.True(t, orphan.Provisioned)
}

func TestProvisionDisableDeletionFalseDeletesOrphanProvisioned(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{
			"slack":   {"host": "slack-file"},
			"webhook": {"host": "webhook-file"},
		},
	}))
	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs:         map[string]map[string]any{"slack": {"host": "slack-file"}},
		DisableDeletion: false,
	}))

	orphan, err := s.GetOutputConfig(ctx, "webhook")
	require.NoError(t, err)
	assert.Nil(t, orphan, "DisableDeletion=false must delete the orphaned Provisioned:true entry")
}

func TestSaveOutputConfigPreservesProvisionedFlag(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{"slack": {"host": "file"}},
	}))
	saveOutput(t, s, "slack", map[string]any{"host": "edited"})
	got, err := s.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	require.True(t, got.Provisioned, "UI edit of file-provisioned entry keeps Provisioned:true")

	saveOutput(t, s, "ui-only-webhook", map[string]any{"address": "http://x"})
	fresh, err := s.GetOutputConfig(ctx, "ui-only-webhook")
	require.NoError(t, err)
	assert.False(t, fresh.Provisioned, "new UI-only entry starts as Provisioned:false")
}

func TestPipelineLayoutRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	layout := &core.PipelineLayout{
		Nodes: []core.LayoutNode{
			{ID: "falco", X: 100, Y: 200},
			{ID: "slack", X: 400, Y: 200},
		},
	}
	require.NoError(t, s.SavePipelineLayout(ctx, layout))

	got, err := s.GetPipelineLayout(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Len(t, got.Nodes, 2)
	assert.Equal(t, "falco", got.Nodes[0].ID)
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestPipelineLayoutDefaultNil(t *testing.T) {
	s := NewMemory()
	got, err := s.GetPipelineLayout(context.Background())
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestGetOutputConfigsReturnsDefensiveCopy(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	saveOutput(t, s, "test", map[string]any{"key": "val"})

	entries1, _ := s.GetOutputConfigs(ctx)
	entries1["injected"] = &core.OutputConfigEntry{Name: "injected"}

	entries2, _ := s.GetOutputConfigs(ctx)
	assert.NotContains(t, entries2, "injected", "external mutation must not affect internal state")
}

func TestCloseIsIdempotent(t *testing.T) {
	s := NewMemory()
	assert.NoError(t, s.Close())
	assert.NoError(t, s.Close())
}

func TestOutputConfigVersionIncrement(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	saveOutput(t, s, "slack", map[string]any{"v": 1})
	saveOutput(t, s, "slack", map[string]any{"v": 2})

	entry, err := s.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	assert.Equal(t, int64(2), entry.Version)
	assert.Equal(t, 2, entry.Config["v"])
}

// A client holding version 1 of a deleted output must not match the output created again.
func TestOutputConfigVersionIsNeverReused(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	first := saveOutput(t, s, "slack", map[string]any{"v": 1})
	require.NoError(t, s.DeleteOutputConfig(ctx, "slack", first))
	saveOutput(t, s, "slack", map[string]any{"v": 2})
	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{Outputs: map[string]map[string]any{"webhook": {}}}))

	slack, err := s.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	webhook, err := s.GetOutputConfig(ctx, "webhook")
	require.NoError(t, err)
	assert.Equal(t, int64(2), slack.Version)
	assert.Equal(t, int64(3), webhook.Version)
}

func TestProvisionKeepsTheVersionOfUnchangedOutputs(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{Outputs: map[string]map[string]any{
		"a": {"host": "https://a"}, "b": {"host": "https://b", "port": 5},
	}}))
	before, err := s.GetOutputConfig(ctx, "b")
	require.NoError(t, err)

	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{Outputs: map[string]map[string]any{
		"a": {"host": "https://a2"}, "b": {"host": "https://b", "port": 5.0},
	}}))
	after, err := s.GetOutputConfig(ctx, "b")
	require.NoError(t, err)
	assert.Equal(t, before.Version, after.Version)
	assert.Equal(t, before.UpdatedAt, after.UpdatedAt)
	a, err := s.GetOutputConfig(ctx, "a")
	require.NoError(t, err)
	assert.Greater(t, a.Version, after.Version, "the changed output gets a new version")
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			_, _ = s.SaveOutputConfig(ctx, "out", int64(i), map[string]any{"i": i})
		}
		close(done)
	}()

	for i := 0; i < 200; i++ {
		_, _ = s.GetOutputConfigs(ctx)
		_, _ = s.GetOutputConfig(ctx, "out")
	}
	<-done

	_, err := s.GetOutputConfig(ctx, "out")
	assert.NoError(t, err)
}

func TestOutputConfigDeepCopyOnProvision(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	original := map[string]any{"nested": map[string]any{"key": "original"}}
	require.NoError(t, s.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{"test": original},
	}))

	original["nested"].(map[string]any)["key"] = "changed-by-caller"

	entry, err := s.GetOutputConfig(ctx, "test")
	require.NoError(t, err)
	assert.Equal(t, "original", entry.Config["nested"].(map[string]any)["key"], "provision must deep-copy")
}

func TestOutputConfigDeepCopyOnGet(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	saveOutput(t, s, "test", map[string]any{"nested": map[string]any{"key": "original"}})

	entry, _ := s.GetOutputConfig(ctx, "test")
	entry.Config["nested"].(map[string]any)["key"] = "changed-after-get"

	entry2, _ := s.GetOutputConfig(ctx, "test")
	assert.Equal(t, "original", entry2.Config["nested"].(map[string]any)["key"], "get must return deep copy")
}
