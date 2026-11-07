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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

func TestDatabaseConfigValidate(t *testing.T) {
	postgres := func(edit func(*core.PostgresConfig)) core.DatabaseConfig {
		cfg := core.DatabaseConfig{Backend: core.DatabasePostgres, ConnectTimeout: time.Second, Postgres: core.PostgresConfig{
			Host: "postgres", Database: "falcosidekick", User: "falcosidekick", Port: 5432,
			SSLMode: core.PostgresSSLVerifyFull, MaxConnections: 4, PollInterval: 10 * time.Second,
		}}
		if edit != nil {
			edit(&cfg.Postgres)
		}
		return cfg
	}
	tests := []struct {
		name string
		want string
		cfg  core.DatabaseConfig
	}{
		{name: "memory", cfg: core.DatabaseConfig{Backend: core.DatabaseInMemory, ConnectTimeout: time.Second}},
		{name: "sqlite", cfg: core.DatabaseConfig{Backend: core.DatabaseSQLite, ConnectTimeout: time.Second, SQLite: core.SQLiteConfig{Path: "db"}}},
		{name: "postgres", cfg: postgres(nil)},
		{name: "postgres with password file and CA", cfg: postgres(func(p *core.PostgresConfig) {
			p.PasswordFile, p.TLS.CAFile, p.SSLMode = "/run/secrets/pg", "/etc/ca.pem", core.PostgresSSLVerifyCA
		})},
		{name: "unknown backend", cfg: core.DatabaseConfig{Backend: "redis", ConnectTimeout: time.Second}, want: "backend: must be inmemory/sqlite/postgres"},
		{name: "empty backend", cfg: core.DatabaseConfig{ConnectTimeout: time.Second}, want: "backend: must be inmemory/sqlite/postgres"},
		{name: "no connect timeout", cfg: core.DatabaseConfig{Backend: core.DatabaseInMemory}, want: "connect_timeout: must be > 0"},
		{name: "sqlite without path", cfg: core.DatabaseConfig{Backend: core.DatabaseSQLite, ConnectTimeout: time.Second}, want: "sqlite.path: must be specified"},
		{name: "postgres without host", cfg: postgres(func(p *core.PostgresConfig) { p.Host = "" }), want: "postgres.host: must be specified"},
		{name: "postgres without database", cfg: postgres(func(p *core.PostgresConfig) { p.Database = "" }), want: "postgres.database: must be specified"},
		{name: "postgres without user", cfg: postgres(func(p *core.PostgresConfig) { p.User = "" }), want: "postgres.user: must be specified"},
		{name: "postgres bad port", cfg: postgres(func(p *core.PostgresConfig) { p.Port = 70000 }), want: "postgres.port: must be 1-65535"},
		{name: "postgres both passwords", cfg: postgres(func(p *core.PostgresConfig) { p.Password, p.PasswordFile = "x", "/f" }),
			want: "postgres.password: set password or password_file, not both"},
		{name: "postgres bad sslmode", cfg: postgres(func(p *core.PostgresConfig) { p.SSLMode = "prefer" }),
			want: "postgres.sslmode: must be disable/require/verify-ca/verify-full"},
		{name: "postgres CA without verification", cfg: postgres(func(p *core.PostgresConfig) { p.SSLMode, p.TLS.CAFile = core.PostgresSSLRequire, "/ca" }),
			want: "postgres.tls.ca_file: is used only with sslmode verify-ca or verify-full"},
		{name: "postgres no connections", cfg: postgres(func(p *core.PostgresConfig) { p.MaxConnections = 0 }), want: "postgres.max_connections: must be >= 1"},
		{name: "postgres no poll", cfg: postgres(func(p *core.PostgresConfig) { p.PollInterval = 0 }), want: "postgres.poll_interval: must be > 0"},
		{name: "postgres settings ignored by sqlite", cfg: core.DatabaseConfig{Backend: core.DatabaseSQLite, ConnectTimeout: time.Second,
			SQLite: core.SQLiteConfig{Path: "db"}, Postgres: core.PostgresConfig{Port: -1}}},
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

// The defaults select inmemory and give a postgres backend safe settings.
func TestLoadDatabaseDefaults(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, core.DatabaseInMemory, cfg.Database.Backend)
	assert.Equal(t, 30*time.Second, cfg.Database.ConnectTimeout)
	assert.Equal(t, core.PostgresConfig{Port: 5432, SSLMode: core.PostgresSSLVerifyFull, MaxConnections: 4, PollInterval: 10 * time.Second},
		cfg.Database.Postgres)
}
