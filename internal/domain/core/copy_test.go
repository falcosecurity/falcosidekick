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

package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mutatedValue = "/mutated"

func TestDeepCopyWithTLS(t *testing.T) {
	original := &Config{
		ListenPort: 2801,
		TLS: &TLSConfig{
			CertFile: "/original/cert.pem",
			Enabled:  true,
		},
	}
	cp := original.DeepCopy()

	original.TLS.CertFile = mutatedValue
	assert.Equal(t, "/original/cert.pem", cp.TLS.CertFile, "DeepCopy must not alias TLS pointer")
}

func TestDeepCopyWithoutTLS(t *testing.T) {
	original := &Config{ListenPort: 2801}
	cp := original.DeepCopy()
	require.Nil(t, cp.TLS)
	assert.Equal(t, 2801, cp.ListenPort)
}

func TestDeepCopyDoesNotAliasSlices(t *testing.T) {
	original := &Config{
		Metrics: MetricsConfig{ExtraLabels: []string{"k8s.ns.name"}},
		API:     APIConfig{SecretDirs: []string{"/run/secrets"}},
	}
	cp := original.DeepCopy()
	original.Metrics.ExtraLabels[0] = mutatedValue
	original.API.SecretDirs[0] = mutatedValue
	assert.Equal(t, []string{"k8s.ns.name"}, cp.Metrics.ExtraLabels)
	assert.Equal(t, []string{"/run/secrets"}, cp.API.SecretDirs)
}

func TestDeepCopyDoesNotAliasScalars(t *testing.T) {
	original := &Config{ListenPort: 2801, LogLevel: LogLevelInfo}
	cp := original.DeepCopy()
	original.ListenPort = 9999
	assert.Equal(t, 2801, cp.ListenPort)
}

func TestOutputConfigEntryDeepCopyIsolatesConfig(t *testing.T) {
	original := OutputConfigEntry{
		Name:        "slack",
		Version:     3,
		Provisioned: true,
		UpdatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Config:      map[string]any{"host": "https://a", "nested": map[string]any{"k": "v"}},
	}

	cp := original.DeepCopy()
	require.NotSame(t, &original, cp)

	cp.Config["host"] = "https://mutated"
	cp.Config["nested"].(map[string]any)["k"] = "mutated"

	assert.Equal(t, "https://a", original.Config["host"], "original top-level map must not be mutated")
	assert.Equal(t, "v", original.Config["nested"].(map[string]any)["k"], "original nested map must not be mutated")
	assert.Equal(t, int64(3), cp.Version)
	assert.True(t, cp.Provisioned)
	assert.Equal(t, "slack", cp.Name)
}

func TestOutputConfigEntryDeepCopyWithNilConfig(t *testing.T) {
	original := OutputConfigEntry{Name: "slack", Version: 1}
	cp := original.DeepCopy()
	require.NotNil(t, cp)
	assert.Nil(t, cp.Config)
	assert.Equal(t, "slack", cp.Name)
}

func TestConfigEntryDeepCopyIsolatesConfig(t *testing.T) {
	original := &ConfigEntry{
		Version:   2,
		UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Config:    &Config{ListenPort: 2801, TLS: &TLSConfig{Enabled: true, CertFile: "/orig"}},
	}

	cp := original.DeepCopy()
	require.NotSame(t, original, cp)
	require.NotSame(t, original.Config, cp.Config)

	cp.Config.TLS.CertFile = mutatedValue
	assert.Equal(t, "/orig", original.Config.TLS.CertFile, "nested TLS pointer must not alias")
	assert.Equal(t, int64(2), cp.Version)
}

func TestConfigEntryDeepCopyWithNilInnerConfig(t *testing.T) {
	original := &ConfigEntry{Version: 1}
	cp := original.DeepCopy()
	require.NotNil(t, cp)
	assert.Nil(t, cp.Config)
	assert.Equal(t, int64(1), cp.Version)
}

func TestPipelineLayoutDeepCopyIsolatesNodes(t *testing.T) {
	original := &PipelineLayout{
		UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Nodes:     []LayoutNode{{ID: "a", X: 1, Y: 2}, {ID: "b", X: 3, Y: 4}},
	}

	cp := original.DeepCopy()
	require.NotSame(t, original, cp)

	cp.Nodes[0].X = 99
	assert.Equal(t, float64(1), original.Nodes[0].X, "Nodes slice must not alias")
	assert.Len(t, cp.Nodes, 2)
}

func TestPipelineLayoutDeepCopyWithNilNodes(t *testing.T) {
	original := &PipelineLayout{UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	cp := original.DeepCopy()
	require.NotNil(t, cp)
	assert.Nil(t, cp.Nodes)
}

func TestOutputConfigEntryGetVersion(t *testing.T) {
	e := OutputConfigEntry{Version: 42}
	assert.Equal(t, int64(42), e.GetVersion())
}

func TestConfigEntryGetVersion(t *testing.T) {
	e := ConfigEntry{Version: 42}
	assert.Equal(t, int64(42), e.GetVersion())
}
