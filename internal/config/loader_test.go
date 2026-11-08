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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0", cfg.ListenAddress)
	assert.Equal(t, 2801, cfg.ListenPort)
	assert.Equal(t, "info", string(cfg.LogLevel))
	assert.Equal(t, "text", string(cfg.LogFormat))
	assert.False(t, cfg.UI.Enabled)
	assert.Equal(t, "inmemory", cfg.UI.EventSource)
	assert.Equal(t, 1000, cfg.RuntimeDefaults.QueueSize)
	assert.Equal(t, 2, cfg.RuntimeDefaults.Workers)
}

func TestLoadFromFile(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(`
listen_port: 3000
log_level: debug
ui:
  enabled: true
runtime_defaults:
  queue_size: 5000
enricher:
  truncate_event_threshold: 8192
`), 0o600))

	cfg, err := Load(cfgFile)
	require.NoError(t, err)

	assert.Equal(t, 3000, cfg.ListenPort)
	assert.Equal(t, "debug", string(cfg.LogLevel))
	assert.True(t, cfg.UI.Enabled)
	assert.Equal(t, 5000, cfg.RuntimeDefaults.QueueSize)
	assert.Equal(t, "0.0.0.0", cfg.ListenAddress)
	assert.Equal(t, 8192, cfg.Enricher.TruncateEventThreshold)
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("FALCOSIDEKICK_LISTEN_PORT", "9999")
	t.Setenv("FALCOSIDEKICK_LOG_LEVEL", "error")

	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, 9999, cfg.ListenPort)
	assert.Equal(t, "error", string(cfg.LogLevel))
}

func TestLoadEnvOverridesFile(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(`listen_port: 3000`), 0o600))

	t.Setenv("FALCOSIDEKICK_LISTEN_PORT", "4000")

	cfg, err := Load(cfgFile)
	require.NoError(t, err)

	assert.Equal(t, 4000, cfg.ListenPort)
}

func TestLoadRejectsUnknownCoreKeys(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte(`
listen_port: 3000
listen_portt: 4000
`), 0o600))

	_, err := Load(cfgFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen_portt")
}

func TestLoadInvalidFilePath(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config read")
}

func TestLoadValidatesWithDefaults(t *testing.T) {
	cfg := loadDefaults(t)

	errs := cfg.Validate()
	assert.Empty(t, errs)
}
