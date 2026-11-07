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
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// PostgresSettings builds the connection settings of cfg. The password, read from cfg.PasswordFile
// when set, is added after parsing, so it never appears in a connection string or its errors.
func PostgresSettings(cfg *core.PostgresConfig) (*pgx.ConnConfig, error) {
	params := [][2]string{
		{"host", cfg.Host},
		{"port", strconv.Itoa(cfg.Port)},
		{"dbname", cfg.Database},
		{"user", cfg.User},
		{"sslmode", string(cfg.SSLMode)},
		{"application_name", "falcosidekick"},
	}
	if cfg.TLS.CAFile != "" {
		params = append(params, [2]string{"sslrootcert", cfg.TLS.CAFile})
	}
	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = p[0] + "=" + quoteParam(p[1])
	}
	settings, err := pgx.ParseConfig(strings.Join(parts, " "))
	if err != nil {
		return nil, fmt.Errorf("database: postgres settings: %w", err)
	}
	settings.Password = cfg.Password
	if cfg.PasswordFile != "" {
		data, err := utils.ReadRegularFile(cfg.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("database: postgres password_file: %s", utils.FileProblem(err))
		}
		settings.Password = strings.TrimRight(string(data), "\r\n")
	}
	return settings, nil
}

// quoteParam quotes a value of a keyword/value connection string.
func quoteParam(value string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value) + "'"
}

// OpenPostgres connects to postgres, which several Sidekick instances can share, using at most
// maxConns connections. The connection settings come built, never as a connection string, so no
// parse error can carry the password.
func OpenPostgres(ctx context.Context, cfg *pgx.ConnConfig, maxConns int) (*SQL, error) {
	if cfg == nil {
		return nil, errors.New("database: postgres settings are missing")
	}
	if maxConns < 1 {
		return nil, errors.New("database: postgres needs at least one connection")
	}
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database: connect to postgres: %w", err)
	}
	return newSQL(ctx, db, postgresDialect)
}
