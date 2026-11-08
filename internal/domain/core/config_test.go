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
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		wantErr   string
		labels    []string
		maxValues int
	}{
		{name: "none"},
		{name: "field names", labels: []string{"k8s.ns.name", "proc.name", "container_id"}},
		{name: "invalid character", labels: []string{"evt.arg[0]"}, wantErr: "not a valid label name"},
		{name: "leading digit", labels: []string{"1field"}, wantErr: "not a valid label name"},
		{name: "reserved prefix", labels: []string{"__name"}, wantErr: "not a valid label name"},
		{name: "empty", labels: []string{""}, wantErr: "not a valid label name"},
		{name: "built-in label", labels: []string{"rule"}, wantErr: "collides with a built-in label"},
		{name: "same label twice", labels: []string{"k8s.ns.name", "k8s_ns_name"}, wantErr: "map to the same label"},
		{name: "no label values", maxValues: -1, wantErr: "max_label_values: must be at least 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxValues := tt.maxValues
			if maxValues == 0 {
				maxValues = 1000
			}
			errs := MetricsConfig{ExtraLabels: tt.labels, MaxLabelValues: maxValues}.Validate()
			if tt.wantErr == "" {
				assert.Empty(t, errs)
				return
			}
			assert.Contains(t, errs.Error(), tt.wantErr)
		})
	}
}

func TestLogLevelValidate(t *testing.T) {
	tests := []struct {
		name    string
		level   LogLevel
		wantErr bool
	}{
		{"debug", LogLevelDebug, false},
		{"info", LogLevelInfo, false},
		{"warn", LogLevelWarn, false},
		{"error", LogLevelError, false},
		{"trace is not a level", LogLevel("trace"), true},
		{"warning is spelled warn", LogLevel("warning"), true},
		{"invalid", LogLevel("invalid"), true},
		{"empty", LogLevel(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.level.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestLogFormatValidate(t *testing.T) {
	tests := []struct {
		name    string
		format  LogFormat
		wantErr bool
	}{
		{"text", LogFormatText, false},
		{"json", LogFormatJSON, false},
		{"invalid", LogFormat("invalid"), true},
		{"empty", LogFormat(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.format.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func TestUIConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     UIConfig
		wantErr bool
	}{
		{"disabled", UIConfig{Enabled: false}, false},
		{"enabled with backend", UIConfig{Enabled: true, EventSource: "memory"}, false},
		{"enabled no backend", UIConfig{Enabled: true, EventSource: ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate()
			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}

func validConfig() Config {
	return Config{
		ListenPort: 2801,
		LogLevel:   LogLevelInfo,
		LogFormat:  LogFormatText,
		Database:   DatabaseConfig{Backend: DatabaseInMemory, ConnectTimeout: time.Second},
		Metrics:    MetricsConfig{MaxLabelValues: 1000},
		Management: ManagementConfig{ListenAddress: "127.0.0.1", ListenPort: 2802},
	}
}

func TestConfigValidateValid(t *testing.T) {
	cfg := validConfig()
	assert.Empty(t, cfg.Validate(), "an empty listen_address listens on every interface")
}

func TestConfigValidateManagementPort(t *testing.T) {
	for _, tc := range []struct {
		want string
		port int
	}{
		{port: 0, want: "management.listen_port: must be 1-65535"},
		{port: 65536, want: "management.listen_port: must be 1-65535"},
		{port: 2801, want: "management.listen_port: must differ from listen_port"},
		{port: 2802},
	} {
		t.Run(strconv.Itoa(tc.port), func(t *testing.T) {
			cfg := Config{
				ListenPort: 2801,
				LogLevel:   LogLevelInfo,
				LogFormat:  LogFormatText,
				Database:   DatabaseConfig{Backend: DatabaseInMemory, ConnectTimeout: time.Second},
				Metrics:    MetricsConfig{MaxLabelValues: 1000},
				Management: ManagementConfig{ListenAddress: "127.0.0.1", ListenPort: tc.port},
			}
			errs := cfg.Validate()
			if tc.want == "" {
				assert.Empty(t, errs)
				return
			}
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Error(), tc.want)
		})
	}
}

func TestManagementConfigRefusesEmptyAddress(t *testing.T) {
	errs := ManagementConfig{ListenPort: 2802}.Validate()
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), `listen_address: is required ("::" for every interface)`)
	assert.Empty(t, ManagementConfig{ListenAddress: "::", ListenPort: 2802}.Validate())
}

func TestShutdownDelayMustNotBeNegative(t *testing.T) {
	cfg := validConfig()
	cfg.ShutdownDelay = -time.Second
	errs := cfg.Validate()
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "shutdown_delay: must be >= 0")
}

func TestAPIConfigValidateSecretDirs(t *testing.T) {
	assert.Empty(t, APIConfig{}.Validate())
	assert.Empty(t, APIConfig{SecretDirs: []string{"/run/secrets"}}.Validate())
	errs := APIConfig{SecretDirs: []string{"/run/secrets", "secrets"}}.Validate()
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), `secret_dirs: "secrets" must be an absolute path`)
}

func TestConfigValidateInvalidPort(t *testing.T) {
	cfg := Config{
		ListenPort: 0,
		LogLevel:   LogLevelInfo,
		LogFormat:  LogFormatText,
		Database:   DatabaseConfig{Backend: DatabaseInMemory, ConnectTimeout: time.Second},
	}
	assert.NotEmpty(t, cfg.Validate())
}

func TestConfigValidateMultipleErrors(t *testing.T) {
	cfg := Config{
		ListenPort: -1,
		LogLevel:   "invalid",
		LogFormat:  "invalid",
		Database:   DatabaseConfig{Backend: "invalid"},
	}
	errs := cfg.Validate()
	assert.True(t, len(errs) >= 4)
}

func TestDatabaseConfigValidate(t *testing.T) {
	postgres := func(edit func(*PostgresConfig)) DatabaseConfig {
		cfg := DatabaseConfig{Backend: DatabasePostgres, ConnectTimeout: time.Second, Postgres: PostgresConfig{
			Host: "postgres", Database: "falcosidekick", User: "falcosidekick", Port: 5432,
			SSLMode: PostgresSSLVerifyFull, MaxConnections: 4, PollInterval: 10 * time.Second,
		}}
		if edit != nil {
			edit(&cfg.Postgres)
		}
		return cfg
	}
	tests := []struct {
		name string
		want string
		cfg  DatabaseConfig
	}{
		{name: "memory", cfg: DatabaseConfig{Backend: DatabaseInMemory, ConnectTimeout: time.Second}},
		{name: "sqlite", cfg: DatabaseConfig{Backend: DatabaseSQLite, ConnectTimeout: time.Second, SQLite: SQLiteConfig{Path: "db"}}},
		{name: "postgres", cfg: postgres(nil)},
		{name: "postgres with password file and CA", cfg: postgres(func(p *PostgresConfig) {
			p.PasswordFile, p.TLS.CAFile, p.SSLMode = "/run/secrets/pg", "/etc/ca.pem", PostgresSSLVerifyCA
		})},
		{name: "unknown backend", cfg: DatabaseConfig{Backend: "redis", ConnectTimeout: time.Second}, want: "backend: must be inmemory/sqlite/postgres"},
		{name: "empty backend", cfg: DatabaseConfig{ConnectTimeout: time.Second}, want: "backend: must be inmemory/sqlite/postgres"},
		{name: "no connect timeout", cfg: DatabaseConfig{Backend: DatabaseInMemory}, want: "connect_timeout: must be > 0"},
		{name: "sqlite without path", cfg: DatabaseConfig{Backend: DatabaseSQLite, ConnectTimeout: time.Second}, want: "sqlite.path: must be specified"},
		{name: "postgres without host", cfg: postgres(func(p *PostgresConfig) { p.Host = "" }), want: "postgres.host: must be specified"},
		{name: "postgres without database", cfg: postgres(func(p *PostgresConfig) { p.Database = "" }), want: "postgres.database: must be specified"},
		{name: "postgres without user", cfg: postgres(func(p *PostgresConfig) { p.User = "" }), want: "postgres.user: must be specified"},
		{name: "postgres bad port", cfg: postgres(func(p *PostgresConfig) { p.Port = 70000 }), want: "postgres.port: must be 1-65535"},
		{name: "postgres both passwords", cfg: postgres(func(p *PostgresConfig) { p.Password, p.PasswordFile = "x", "/f" }),
			want: "postgres.password: set password or password_file, not both"},
		{name: "postgres bad sslmode", cfg: postgres(func(p *PostgresConfig) { p.SSLMode = "prefer" }),
			want: "postgres.sslmode: must be disable/require/verify-ca/verify-full"},
		{name: "postgres CA without verification", cfg: postgres(func(p *PostgresConfig) { p.SSLMode, p.TLS.CAFile = PostgresSSLRequire, "/ca" }),
			want: "postgres.tls.ca_file: is used only with sslmode verify-ca or verify-full"},
		{name: "postgres no connections", cfg: postgres(func(p *PostgresConfig) { p.MaxConnections = 0 }), want: "postgres.max_connections: must be >= 1"},
		{name: "postgres no poll", cfg: postgres(func(p *PostgresConfig) { p.PollInterval = 0 }), want: "postgres.poll_interval: must be > 0"},
		{name: "postgres settings ignored by sqlite", cfg: DatabaseConfig{Backend: DatabaseSQLite, ConnectTimeout: time.Second,
			SQLite: SQLiteConfig{Path: "db"}, Postgres: PostgresConfig{Port: -1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate()
			if tt.want == "" {
				assert.Empty(t, errs)
				return
			}
			assert.Equal(t, tt.want, errs.Error())
		})
	}
}
