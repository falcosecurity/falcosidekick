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
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// Pure Go sqlite driver, so builds keep CGO_ENABLED=0.
	_ "modernc.org/sqlite"
)

// OpenSQLite opens or creates the sqlite database file at path for one Sidekick instance. A new file
// is created with mode 0600; sqlite gives its -wal and -shm files the mode of the database file.
// The path is made absolute, so names sqlite reads specially, such as ":memory:" or "file:...",
// are ordinary files.
func OpenSQLite(ctx context.Context, path string) (*SQL, error) {
	if path == "" {
		return nil, errors.New("database: sqlite path is empty")
	}
	if strings.ContainsAny(path, "?#") {
		return nil, errors.New("database: sqlite path must not contain '?' or '#'")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("database: sqlite path: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // operator-provided database path
	if err != nil {
		return nil, fmt.Errorf("database: open sqlite file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("database: open sqlite file: %w", err)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		return nil, fmt.Errorf("database: open sqlite: %w", err)
	}
	// One connection: every write is serialized, and a transaction never waits on another one.
	db.SetMaxOpenConns(1)
	return newSQL(ctx, db, sqliteDialect)
}
