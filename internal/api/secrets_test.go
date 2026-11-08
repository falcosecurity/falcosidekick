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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

func secretType(name string) output.Type {
	return output.Type{
		Name: name,
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return nil, assert.AnError
		},
		Schema: output.Schema{
			Fields: []output.SchemaField{
				{Name: "host", Type: "string"},
				{Name: "password", Type: "string", Secret: true},
				{Name: "token", Type: "string", Secret: true},
			},
		},
	}
}

func publicType(name string) output.Type {
	return output.Type{
		Name: name,
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return nil, assert.AnError
		},
		Schema: output.Schema{
			Fields: []output.SchemaField{
				{Name: "host", Type: "string"},
				{Name: "channel", Type: "string"},
			},
		},
	}
}

func TestMaskOutputConfig_NoSecretSchemaFields(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "slack",
		Config: map[string]any{
			"host":    "https://hooks.slack.com/x",
			"channel": "#alerts",
		},
		UpdatedAt: time.Now(),
	}

	masked := maskOutputConfig(entry, new(publicType("slack")))

	assert.Equal(t, "https://hooks.slack.com/x", masked.Config["host"])
	assert.Equal(t, "#alerts", masked.Config["channel"])
}

func TestMaskOutputConfig_SecretFieldPresent(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "elasticsearch",
		Config: map[string]any{
			"host":     "https://es:9200",
			"password": "hunter2",
		},
	}

	masked := maskOutputConfig(entry, new(secretType("elasticsearch")))

	assert.Equal(t, "https://es:9200", masked.Config["host"])
	assert.NotContains(t, masked.Config, "password")
	assert.True(t, masked.SecretFields["/password"])
}

func TestMaskOutputConfig_SecretFieldAbsent(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "elasticsearch",
		Config: map[string]any{
			"host": "https://es:9200",
			// password intentionally omitted
		},
	}

	masked := maskOutputConfig(entry, new(secretType("elasticsearch")))

	_, hasPassword := masked.Config["password"]
	assert.False(t, hasPassword, "absent secret field must not be synthesized by the mask helper")
	assert.Equal(t, "https://es:9200", masked.Config["host"])
}

func TestMaskOutputConfig_MultipleSecretFields(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "elasticsearch",
		Config: map[string]any{
			"host":     "https://es:9200",
			"password": "p",
			"token":    "t",
		},
	}

	masked := maskOutputConfig(entry, new(secretType("elasticsearch")))

	assert.NotContains(t, masked.Config, "password")
	assert.NotContains(t, masked.Config, "token")
	assert.Equal(t, map[string]bool{"/password": true, "/token": true}, masked.SecretFields)
}

func TestMaskOutputConfig_UnknownType_ProtectsAllLeaves(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "legacy",
		Config: map[string]any{
			"host":   "https://x",
			"port":   9200,
			"enable": true,
		},
	}

	masked := maskOutputConfig(entry, &output.Type{})

	assert.Empty(t, masked.Config)
	assert.Equal(t, map[string]bool{"/host": true, "/port": true, "/enable": true}, masked.SecretFields)
}

func TestMaskOutputConfig_CaseInsensitiveMatch(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "weird",
		Config: map[string]any{
			"Password": "plaintext",
			"password": "secret",
		},
	}

	masked := maskOutputConfig(entry, new(secretType("weird")))

	assert.Empty(t, masked.Config)
	assert.Equal(t, map[string]bool{"/Password": true, "/password": true}, masked.SecretFields)
}

func TestMaskOutputConfig_DoesNotMutateInput(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "elasticsearch",
		Config: map[string]any{
			"password": "original",
			"host":     "https://es:9200",
		},
	}

	_ = maskOutputConfig(entry, new(secretType("elasticsearch")))

	assert.Equal(t, "original", entry.Config["password"], "original entry must not be mutated")
}

func TestMaskOutputConfig_NilConfig(t *testing.T) {
	entry := &core.OutputConfigEntry{Name: "x", Config: nil}

	masked := maskOutputConfig(entry, new(secretType("x")))

	assert.Nil(t, masked.Config)
}

func TestMaskOutputConfigs_LooksUpPerType(t *testing.T) {
	cat, err := catalog.New([]output.Type{secretType("elasticsearch"), publicType("slack")})
	require.NoError(t, err)

	entries := map[string]*core.OutputConfigEntry{
		"elasticsearch": {Name: "elasticsearch", Config: map[string]any{"password": "x", "host": "u"}},
		"slack":         {Name: "slack", Config: map[string]any{"host": "https://s", "channel": "#c"}},
		"unknown":       {Name: "unknown", Config: map[string]any{"token": "t", "port": 80}},
	}

	masked := maskOutputConfigs(entries, cat)

	assert.NotContains(t, masked["elasticsearch"].Config, "password")
	assert.True(t, masked["elasticsearch"].SecretFields["/password"])
	assert.Equal(t, "u", masked["elasticsearch"].Config["host"])
	assert.Equal(t, "https://s", masked["slack"].Config["host"])
	assert.Equal(t, "#c", masked["slack"].Config["channel"])
	assert.Empty(t, masked["unknown"].Config)
	assert.Equal(t, map[string]bool{"/token": true, "/port": true}, masked["unknown"].SecretFields)
}

func TestMaskOutputConfigs_NilInput(t *testing.T) {
	cat, err := catalog.New([]output.Type{publicType("slack")})
	require.NoError(t, err)

	assert.Nil(t, maskOutputConfigs(nil, cat))
}

func TestMaskCoreConfig_CopiesAndReturnsEquivalent(t *testing.T) {
	cfg := &core.Config{
		ListenAddress: "0.0.0.0",
		ListenPort:    2801,
		LogLevel:      core.LogLevelInfo,
		LogFormat:     core.LogFormatText,
	}

	masked := maskCoreConfig(cfg)

	require.NotNil(t, masked)
	assert.NotSame(t, cfg, masked, "masker must return a copy, not the same pointer")
	assert.Equal(t, cfg.ListenAddress, masked.ListenAddress)
	assert.Equal(t, cfg.ListenPort, masked.ListenPort)
}

func TestMaskCoreConfig_Nil(t *testing.T) {
	assert.Nil(t, maskCoreConfig(nil))
}

func TestMaskOutputConfig_ConfiguredPresence(t *testing.T) {
	for _, tc := range []struct {
		value      any
		name       string
		configured bool
	}{
		{"secret", "string", true},
		{"", "empty string", false},
		{0, "zero", true},
		{false, "false", true},
		{float64(0), "zero float", true},
		{nil, "null", false},
		{[]string{}, "empty list", false},
		{[]string(nil), "nil list", false},
		{[]string{"secret"}, "list", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := &core.OutputConfigEntry{Config: map[string]any{"password": tc.value}}
			masked := maskOutputConfig(entry, new(secretType("webhook")))
			assert.NotContains(t, masked.Config, "password")
			assert.Equal(t, map[string]bool{"/password": tc.configured}, masked.SecretFields)
		})
	}
}

func nestedSecretType() output.Type {
	return output.Type{
		Name: "kafka",
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return nil, assert.AnError
		},
		Schema: output.Schema{
			Fields: []output.SchemaField{
				{Name: "topic", Type: "string"},
				{Name: "auth.sasl", Type: "string"},
				{Name: "auth.username", Type: "string"},
				{Name: "auth.password", Type: "string", Secret: true},
			},
		},
	}
}

func TestMaskOutputConfig_NestedSecretPath(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name: "kafka",
		Config: map[string]any{
			"topic": "falco-events",
			"auth": map[string]any{
				"sasl":     "plain",
				"username": "alice",
				"password": "real-password",
			},
		},
	}

	masked := maskOutputConfig(entry, new(nestedSecretType()))

	auth := masked.Config["auth"].(map[string]any)
	assert.NotContains(t, auth, "password")
	assert.True(t, masked.SecretFields["/auth/password"])
	assert.Equal(t, "plain", auth["sasl"], "non-secret nested siblings must not be touched")
	assert.Equal(t, "alice", auth["username"])

	origAuth := entry.Config["auth"].(map[string]any)
	assert.Equal(t, "real-password", origAuth["password"], "original entry must not be mutated")
}

func TestMaskOutputConfig_NestedSecretPathAbsentParent(t *testing.T) {
	entry := &core.OutputConfigEntry{
		Name:   "kafka",
		Config: map[string]any{"topic": "t"},
	}
	masked := maskOutputConfig(entry, new(nestedSecretType()))
	_, hasAuth := masked.Config["auth"]
	assert.False(t, hasAuth, "absent parent must not be synthesized by the masker")
}

func TestContainsSecretPlaceholder_NestedPath(t *testing.T) {
	cfg := map[string]any{
		"topic": "t",
		"auth": map[string]any{
			"username": "alice",
			"password": SecretMask,
		},
	}
	field := containsSecretPlaceholder(cfg, new(nestedSecretType()))
	assert.Equal(t, "auth.password", field)
}

func TestContainsSecretPlaceholder_NestedPathAbsentIsSafe(t *testing.T) {
	cfg := map[string]any{
		"topic": "t",
		"auth":  map[string]any{"username": "alice"},
	}
	assert.Empty(t, containsSecretPlaceholder(cfg, new(nestedSecretType())),
		"absent nested secret is a valid keep-existing PUT; must not be rejected")
}

func TestConfigPointer(t *testing.T) {
	tests := []struct {
		name string
		want string
		path []string
	}{
		{name: "document root", path: nil, want: ""},
		{name: "single segment", path: []string{"password"}, want: "/password"},
		{name: "nested", path: []string{"headers", "secrets"}, want: "/headers/secrets"},
		{name: "empty segment", path: []string{""}, want: "/"},
		{name: "tilde and slash escaped", path: []string{"a~b/c"}, want: "/a~0b~1c"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, configPointer(tc.path))
		})
	}
}

func TestMaskCoreConfig_HidesThePostgresPassword(t *testing.T) {
	cfg := &core.Config{Database: core.DatabaseConfig{Postgres: core.PostgresConfig{Password: "private-value", PasswordFile: "/run/secrets/pg"}}}
	masked := maskCoreConfig(cfg)
	assert.Equal(t, SecretMask, masked.Database.Postgres.Password)
	assert.Equal(t, "/run/secrets/pg", masked.Database.Postgres.PasswordFile)
	assert.Equal(t, "private-value", cfg.Database.Postgres.Password, "the running configuration is untouched")
	assert.Empty(t, maskCoreConfig(&core.Config{}).Database.Postgres.Password, "no password, nothing to mask")
}
