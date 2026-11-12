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

	assert.Empty(t, cfg.ListenAddress)
	assert.Equal(t, 2801, cfg.ListenPort)
	assert.Equal(t, "127.0.0.1", cfg.Management.ListenAddress, "the API listens on loopback by default")
	assert.Equal(t, 2802, cfg.Management.ListenPort)
	assert.Equal(t, 1000, cfg.Metrics.MaxLabelValues)
	assert.Equal(t, "info", string(cfg.LogLevel))
	assert.Equal(t, "text", string(cfg.LogFormat))
	assert.False(t, cfg.UI.Enabled)
	assert.False(t, cfg.API.AllowWrites, "API writes are off unless enabled")
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
api:
  allow_writes: true
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
	assert.True(t, cfg.API.AllowWrites)
	assert.Equal(t, 5000, cfg.RuntimeDefaults.QueueSize)
	assert.Empty(t, cfg.ListenAddress)
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

// Keys without a default are read from the environment too.
func TestLoadEnvOnlyKeys(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Nil(t, cfg.TLS, "no TLS block without TLS settings")

	t.Setenv("FALCOSIDEKICK_TLS_ENABLED", "true")
	t.Setenv("FALCOSIDEKICK_TLS_CERT_FILE", "/certs/tls.crt")
	t.Setenv("FALCOSIDEKICK_PROVISIONING_ALLOW_UI_UPDATES", "true")
	t.Setenv("FALCOSIDEKICK_RUNTIME_DEFAULTS_MINIMUM_PRIORITY", "warning")
	t.Setenv("FALCOSIDEKICK_RUNTIME_DEFAULTS_HEALTH_CHECK", "false")

	cfg, err = Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg.TLS)
	assert.True(t, cfg.TLS.Enabled)
	assert.Equal(t, "/certs/tls.crt", cfg.TLS.CertFile)
	assert.True(t, cfg.Provisioning.AllowUIUpdates)
	assert.Equal(t, "Warning", cfg.RuntimeDefaults.MinPriority.String())
	require.NotNil(t, cfg.RuntimeDefaults.HealthCheck)
	assert.False(t, *cfg.RuntimeDefaults.HealthCheck)
}

func TestLoadMetricsExtraLabels(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Empty(t, cfg.Metrics.ExtraLabels)

	cfgFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("metrics:\n  extra_labels: [k8s.ns.name, proc.name]\n"), 0o600))
	cfg, err = Load(cfgFile)
	require.NoError(t, err)
	assert.Equal(t, []string{"k8s.ns.name", "proc.name"}, cfg.Metrics.ExtraLabels)

	t.Setenv("FALCOSIDEKICK_METRICS_EXTRA_LABELS", "k8s.pod.name,container.id")
	cfg, err = Load("")
	require.NoError(t, err)
	assert.Equal(t, []string{"k8s.pod.name", "container.id"}, cfg.Metrics.ExtraLabels)
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

func TestLoadFileKeysAreCaseInsensitiveAndEnvWins(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "sidekick.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("Listen_Port: 2802\nLog_Level: debug\nruntime_defaults:\n  Queue_Size: 7\n"), 0o600))
	t.Setenv("FALCOSIDEKICK_LOG_LEVEL", "error")

	cfg, err := Load(cfgFile)
	require.NoError(t, err)
	assert.Equal(t, 2802, cfg.ListenPort)
	assert.Equal(t, 7, cfg.RuntimeDefaults.QueueSize, "nested keys merge over the defaults")
	assert.Equal(t, 2, cfg.RuntimeDefaults.Workers, "nested defaults the file does not set are kept")
	assert.Equal(t, "error", string(cfg.LogLevel), "the environment overrides the file")
}

func TestLoadParseErrorsNeverQuoteTheFile(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	for _, tc := range []struct {
		name, content, want string
	}{
		{name: "unknown alias", content: "log_level: *" + sentinel + "\n", want: "yaml: line 1: invalid anchor or alias"},
		{name: "unterminated quote", content: "log_level: \"" + sentinel + "\n", want: "yaml: lines 1-2: invalid syntax"},
		{name: "duplicate key", content: "log_level: info\nlog_level: " + sentinel + "\n", want: "yaml: line 2: invalid structure"},
		{name: "duration with spaces", content: "reload:\n  retire_timeout: \"" + sentinel + " x\"\n", want: "reload.retire_timeout"},
		{name: "number", content: "listen_port: " + sentinel + "\n", want: "listen_port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgFile := filepath.Join(t.TempDir(), "sidekick.yaml")
			require.NoError(t, os.WriteFile(cfgFile, []byte(tc.content), 0o600))
			_, err := Load(cfgFile)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), sentinel)
		})
	}
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

func TestLoadRefusesLossyNumbers(t *testing.T) {
	for _, tt := range []struct {
		name, file, env, want string
	}{
		{name: "fraction", file: "listen_port: 2801.5\n", want: "listen_port: must be an integer"},
		{name: "beyond int64", file: "runtime_defaults:\n  workers: 99999999999999999999\n", want: "runtime_defaults.workers: is out of range"},
		{name: "wrapping uint64", file: "runtime_defaults:\n  queue_size: 9223372036854775808\n", want: "runtime_defaults.queue_size: is out of range"},
		{name: "bool for a number", file: "metrics:\n  max_label_values: true\n", want: "metrics.max_label_values: must be an integer"},
		{name: "infinite multiplier", file: "runtime_defaults:\n  retry:\n    multiplier: .inf\n", want: "runtime_defaults.retry.multiplier: must be a finite number"},
		{name: "NaN multiplier", file: "runtime_defaults:\n  retry:\n    multiplier: .nan\n", want: "runtime_defaults.retry.multiplier: must be a finite number"},
		{name: "env beyond int64", env: "99999999999999999999", want: "runtime_defaults.workers: is out of range"},
		{name: "env fraction", env: "1.5", want: "runtime_defaults.workers: must be an integer"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := ""
			if tt.file != "" {
				path = filepath.Join(t.TempDir(), "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))
			}
			if tt.env != "" {
				t.Setenv("FALCOSIDEKICK_RUNTIME_DEFAULTS_WORKERS", tt.env)
			}
			_, err := Load(path)
			require.Error(t, err)
			assert.Equal(t, "config: "+tt.want, err.Error())
		})
	}
}

func TestLoadRefusesValuesOfAnotherType(t *testing.T) {
	for _, tt := range []struct {
		check          func(t *testing.T, cfg *Config)
		name, file     string
		envKey, envVal string
		want           string
	}{
		{name: "number for a boolean", file: "tls:\n  enabled: 2\n", want: "tls.enabled: must be true or false"},
		{name: "one for a boolean", file: "api:\n  allow_writes: 1\n", want: "api.allow_writes: must be true or false"},
		{name: "zero for a boolean pointer", file: "runtime_defaults:\n  health_check: 0\n", want: "runtime_defaults.health_check: must be true or false"},
		{name: "float for a boolean", file: "ui:\n  enabled: 1.0\n", want: "ui.enabled: must be true or false"},
		{name: "word for a boolean", file: "ui:\n  enabled: yes\n", want: "ui.enabled: must be true or false"},
		{name: "quoted boolean", file: "ui:\n  enabled: \"true\"\n", check: func(t *testing.T, cfg *Config) { assert.True(t, cfg.UI.Enabled) }},
		{name: "env number for a boolean", envKey: "FALCOSIDEKICK_UI_ENABLED", envVal: "2", want: "ui.enabled: must be true or false"},
		{name: "env word for a boolean", envKey: "FALCOSIDEKICK_UI_ENABLED", envVal: "on", want: "ui.enabled: must be true or false"},
		{name: "env boolean", envKey: "FALCOSIDEKICK_UI_ENABLED", envVal: "True", check: func(t *testing.T, cfg *Config) { assert.True(t, cfg.UI.Enabled) }},
		{name: "env one is true as strconv.ParseBool reads it", envKey: "FALCOSIDEKICK_UI_ENABLED", envVal: "1", check: func(t *testing.T, cfg *Config) { assert.True(t, cfg.UI.Enabled) }},
		{name: "number for a duration", file: "shutdown_delay: 30\n", want: "shutdown_delay: must be a duration such as 30s or 1m"},
		{name: "zero for a duration", file: "reload:\n  poll_interval: 0\n", check: func(t *testing.T, cfg *Config) { assert.Zero(t, cfg.Reload.PollInterval) }},
		{name: "env number for a duration", envKey: "FALCOSIDEKICK_SHUTDOWN_DELAY", envVal: "30", want: "shutdown_delay: must be a duration such as 30s or 1m"},
		{name: "number for a list", file: "metrics:\n  extra_labels: 5\n", want: "metrics.extra_labels: must be a list"},
		{name: "map for a list", file: "metrics:\n  extra_labels: {a: 1}\n", want: "metrics.extra_labels: must be a list"},
		{name: "text for a list splits as the environment does", file: "metrics:\n  extra_labels: a,b\n",
			check: func(t *testing.T, cfg *Config) { assert.Equal(t, []string{"a", "b"}, cfg.Metrics.ExtraLabels) }},
		{name: "number for a string is its text", file: "log_level: 1\n", want: "log_level: must be debug/info/warn/error"},
		{name: "list for a map", file: "enricher:\n  custom_fields: [{a: b}]\n", want: "enricher.custom_fields: invalid type, expected map"},
		{name: "list for a string", file: "listen_address: [a]\n", want: "listen_address: invalid type, expected string"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := ""
			if tt.file != "" {
				path = filepath.Join(t.TempDir(), "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))
			}
			if tt.envKey != "" {
				t.Setenv(tt.envKey, tt.envVal)
			}
			cfg, err := Load(path)
			if tt.want == "" {
				require.NoError(t, err)
				tt.check(t, cfg)
				return
			}
			if err == nil {
				err = cfg.Validate()
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestLoadValidatesBounds(t *testing.T) {
	for _, tt := range []struct {
		name, file, want string
	}{
		{name: "workers max", file: "runtime_defaults:\n  workers: 256\n"},
		{name: "workers above max", file: "runtime_defaults:\n  workers: 257\n", want: "runtime_defaults.workers: must be an integer between 1 and 256"},
		{name: "batch size zero while batching is off", file: "runtime_defaults:\n  batching:\n    batch_size: 0\n",
			want: "runtime_defaults.batching.batch_size: must be an integer between 1 and 10000"},
		{name: "batched events above the limit", file: "runtime_defaults:\n  workers: 20\n  batching:\n    enabled: true\n    batch_size: 5001\n",
			want: "runtime_defaults.batching.batch_size: must be at most 5000 with 20 workers: workers × batch_size is limited to 100000"},
		{name: "label values above max", file: "metrics:\n  max_label_values: 10001\n", want: "metrics.max_label_values: must be an integer between 1 and 10000"},
		{name: "retry interval integer zero", file: "runtime_defaults:\n  retry:\n    initial_interval: 0\n",
			want: "runtime_defaults.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "retry interval zero text", file: "runtime_defaults:\n  retry:\n    initial_interval: \"0s\"\n",
			want: "runtime_defaults.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "reset timeout integer zero", file: "runtime_defaults:\n  circuit_breaker:\n    reset_timeout: 0\n",
			want: "runtime_defaults.circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
		{name: "flush interval integer zero", file: "runtime_defaults:\n  batching:\n    flush_interval: 0\n",
			want: "runtime_defaults.batching.flush_interval: must be a duration between 10ms and 1h"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))
			cfg, err := Load(path)
			require.NoError(t, err)
			errs := cfg.Validate()
			if tt.want == "" {
				assert.Empty(t, errs)
				return
			}
			assert.Equal(t, tt.want, errs.Error())
		})
	}
}

func TestLoadRefusesUnknownKeysEvenWhenNull(t *testing.T) {
	for file, want := range map[string]string{
		"typo: null\n":                         "unknown keys: typo",
		"runtime_defaults:\n  wrokers: null\n": "unknown keys: wrokers",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(file), 0o600))
		_, err := Load(path)
		require.Error(t, err, file)
		assert.Contains(t, err.Error(), want)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("log_level: null\nmetrics:\n  max_label_values: null\n"), 0o600))
	cfg, err := Load(path)
	require.NoError(t, err, "a null known key is omitted")
	assert.Equal(t, 1000, cfg.Metrics.MaxLabelValues)
}
