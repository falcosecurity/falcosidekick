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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const invalidValue = "invalid"

func loadDefaults(t *testing.T) *Config {
	t.Helper()
	cfg, err := Load("")
	require.NoError(t, err)
	return cfg
}

func TestLoadEmptyPathUsesDefaults(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, 2801, cfg.ListenPort)
	assert.Empty(t, cfg.ListenAddress, "every interface, IPv4 and IPv6")
	assert.Equal(t, 5*time.Second, cfg.ShutdownDelay)
}

func TestDefaultEnricherFromConfig(t *testing.T) {
	cfg := loadDefaults(t)

	assert.Zero(t, cfg.Enricher.TruncateEventThreshold, "truncation drops evidence, so it is opt-in")
	assert.Equal(t, 512, cfg.Enricher.TruncateFieldThreshold)
}

func TestEnricherKeysAreSnakeCase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sidekick.yaml")
	require.NoError(t, os.WriteFile(path, []byte("enricher:\n  custom_fields: {env: prod}\n  custom_tags: [security]\n"+
		"  templated_fields: {ns: '{{ index . \"k8s.ns.name\" }}'}\n  bracket_replacer: _\n"), 0o600))
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"env": "prod"}, cfg.Enricher.CustomFields)
	assert.Equal(t, []string{"security"}, cfg.Enricher.CustomTags)
	assert.Contains(t, cfg.Enricher.TemplatedFields, "ns")
	assert.Equal(t, "_", cfg.Enricher.BracketReplacer)

	require.NoError(t, os.WriteFile(path, []byte("enricher:\n  customfields: {env: prod}\n"), 0o600))
	_, err = Load(path)
	require.Error(t, err, "the old v2 spelling is refused, not ignored")
	assert.Contains(t, err.Error(), "customfields")
}

func TestDefaultPipelineWorkerFromConfig(t *testing.T) {
	cfg := loadDefaults(t)

	assert.Equal(t, 1000, cfg.RuntimeDefaults.QueueSize)
	assert.Equal(t, 2, cfg.RuntimeDefaults.Workers)
	assert.Equal(t, 3, cfg.RuntimeDefaults.Retry.MaxAttempts)
	assert.Equal(t, time.Second, cfg.RuntimeDefaults.Retry.InitialInterval)
	assert.Equal(t, 30*time.Second, cfg.RuntimeDefaults.Retry.MaxInterval)
	assert.Equal(t, 2.0, cfg.RuntimeDefaults.Retry.Multiplier)
	assert.Equal(t, 5, cfg.RuntimeDefaults.CircuitBreaker.FailureThreshold)
	assert.Equal(t, 2, cfg.RuntimeDefaults.CircuitBreaker.SuccessThreshold)
	assert.Equal(t, 30*time.Second, cfg.RuntimeDefaults.CircuitBreaker.ResetTimeout)
}

func TestDefaultUIFromConfig(t *testing.T) {
	cfg := loadDefaults(t)

	assert.False(t, cfg.UI.Enabled)
	assert.Equal(t, "inmemory", cfg.UI.EventSource)
}

func TestDefaultTLSFromConfig(t *testing.T) {
	cfg := loadDefaults(t)

	assert.Nil(t, cfg.TLS)
}

func TestDefaultsPassValidation(t *testing.T) {
	cfg := loadDefaults(t)

	errs := cfg.Validate()
	assert.Empty(t, errs)
}

func TestValidatePortRange(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"valid", 2801, false},
		{"min", 1, false},
		{"max", 65535, false},
		{"zero", 0, true},
		{"negative", -1, true},
		{"too large", 65536, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadDefaults(t)
			cfg.ListenPort = tt.port
			errs := cfg.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.ListenPort = 0
	cfg.LogLevel = invalidValue
	cfg.LogFormat = invalidValue

	errs := cfg.Validate()
	assert.GreaterOrEqual(t, len(errs), 3)
}

func TestValidateTLSNilPassesCleanly(t *testing.T) {
	cfg := loadDefaults(t)
	cfg.TLS = nil

	errs := cfg.Validate()
	assert.Empty(t, errs)
}
