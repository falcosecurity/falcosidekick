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
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

// OutputsChannel is the postgres notification channel of output changes.
const OutputsChannel = "falcosidekick_outputs"

//go:embed migrations
var migrations embed.FS

// dialect holds what differs between the SQL backends.
type dialect struct {
	// tx pins the isolation the writes rely on, whatever the server default is; nil for sqlite,
	// where one connection serializes every transaction.
	tx *sql.TxOptions
	// commitUnknown reports a commit error after which the transaction may have been applied.
	commitUnknown func(error) bool
	name          string
	// nextVersion returns the next store-wide version inside a write transaction.
	nextVersion string
	// lock serializes provisioning and migrations across instances inside a transaction; empty when
	// the backend has a single writer.
	lock string
	// jsonValue is the placeholder of a JSON column value.
	jsonValue string
	// notify is run inside each output write with the output name, so other instances learn about it.
	notify string
	// numbered rewrites ? placeholders as $1, $2, ...
	numbered bool
}

var (
	sqliteDialect = &dialect{
		name:        "sqlite",
		nextVersion: "UPDATE falcosidekick_version SET value = value + 1 RETURNING value",
		jsonValue:   "?",
	}
	postgresDialect = &dialect{
		name:        "postgres",
		nextVersion: "SELECT nextval('falcosidekick_version')",
		lock:        "SELECT pg_advisory_xact_lock(4615402773652741201)",
		jsonValue:   "CAST(? AS JSONB)",
		tx:          &sql.TxOptions{Isolation: sql.LevelReadCommitted},
		notify:      "SELECT pg_notify('" + OutputsChannel + "', ?)",
		commitUnknown: func(err error) bool {
			var pgErr *pgconn.PgError
			return !errors.As(err, &pgErr)
		},
		numbered: true,
	}
)

// q returns query with the dialect's placeholders.
func (d *dialect) q(query string) string {
	query = strings.ReplaceAll(query, "{json}", d.jsonValue)
	if !d.numbered {
		return query
	}
	parts := strings.Split(query, "?")
	for i := 1; i < len(parts); i++ {
		parts[i] = "$" + strconv.Itoa(i) + parts[i]
	}
	return strings.Join(parts, "")
}

// SQL is a core.Database on sqlite or postgres. Configs are stored as JSON, versions come from one
// store-wide sequence and are never reused.
type SQL struct {
	db      *sql.DB
	dialect *dialect
}

func newSQL(ctx context.Context, db *sql.DB, d *dialect) (*SQL, error) {
	s := &SQL{db: db, dialect: d}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// migrate applies the embedded migrations not applied yet, in one transaction. A schema newer than
// these migrations stops startup without any change.
func (s *SQL) migrate(ctx context.Context) error {
	files, err := fs.Glob(migrations, path.Join("migrations", s.dialect.name, "*.sql"))
	if err != nil {
		return fmt.Errorf("database: list migrations: %w", err)
	}
	slices.Sort(files)

	return s.inTx(ctx, func(tx *sql.Tx) error {
		if s.dialect.lock != "" {
			if _, err := tx.ExecContext(ctx, s.dialect.lock); err != nil {
				return fmt.Errorf("database: lock migrations: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS falcosidekick_schema (version INTEGER NOT NULL)"); err != nil {
			return fmt.Errorf("database: create schema table: %w", err)
		}
		var current int
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM falcosidekick_schema").Scan(&current); err != nil {
			return fmt.Errorf("database: read schema version: %w", err)
		}
		if current > len(files) {
			return fmt.Errorf("database: schema version %d is newer than this Sidekick, which knows up to %d", current, len(files))
		}
		for i := current; i < len(files); i++ {
			script, err := migrations.ReadFile(files[i])
			if err != nil {
				return fmt.Errorf("database: read migration %d: %w", i+1, err)
			}
			if _, err := tx.ExecContext(ctx, string(script)); err != nil {
				return fmt.Errorf("database: migration %d: %w", i+1, err)
			}
			if _, err := tx.ExecContext(ctx, s.dialect.q("INSERT INTO falcosidekick_schema (version) VALUES (?)"), i+1); err != nil {
				return fmt.Errorf("database: record migration %d: %w", i+1, err)
			}
		}
		return nil
	})
}

func (s *SQL) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, s.dialect.tx)
	if err != nil {
		return fmt.Errorf("database: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		if s.dialect.commitUnknown != nil && s.dialect.commitUnknown(err) {
			return fmt.Errorf("database: commit: %w: %w", core.ErrOutcomeUnknown, err)
		}
		return fmt.Errorf("database: commit: %w", err)
	}
	return nil
}

// notifyChange tells the other instances, at commit, that the named output changed.
func (s *SQL) notifyChange(ctx context.Context, tx *sql.Tx, name string) error {
	if s.dialect.notify == "" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, s.dialect.q(s.dialect.notify), name); err != nil {
		return fmt.Errorf("database: notify: %w", err)
	}
	return nil
}

func (s *SQL) nextVersion(ctx context.Context, tx *sql.Tx) (int64, error) {
	var v int64
	if err := tx.QueryRowContext(ctx, s.dialect.nextVersion).Scan(&v); err != nil {
		return 0, fmt.Errorf("database: next version: %w", err)
	}
	return v, nil
}

// Provision stores the outputs from files as provisioned, rewriting only those whose settings
// changed, and deletes the provisioned outputs missing from them. API outputs are kept, unless the
// files define the same name. Each write is an upsert, so an API write committed after the read
// cannot make it fail or be lost.
func (s *SQL) Provision(ctx context.Context, req *core.ProvisionRequest) error {
	if req == nil {
		return errors.New("database: provision request is nil")
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if s.dialect.lock != "" {
			if _, err := tx.ExecContext(ctx, s.dialect.lock); err != nil {
				return fmt.Errorf("database: lock provisioning: %w", err)
			}
		}
		existing, err := s.readOutputs(ctx, tx, "")
		if err != nil {
			return err
		}
		for name, entry := range existing {
			if _, kept := req.Outputs[name]; kept || !entry.Provisioned {
				continue
			}
			// An API output another instance stored under this name meanwhile is not a provisioned output to delete.
			if _, err := tx.ExecContext(ctx, s.dialect.q("DELETE FROM falcosidekick_outputs WHERE name = ? AND provisioned = ?"), name, true); err != nil {
				return fmt.Errorf("database: delete output: %w", err)
			}
		}
		now := time.Now().UnixNano()
		for name, cfg := range req.Outputs {
			entry, found := existing[name]
			if found && entry.Provisioned && sameConfig(entry.Config, cfg) {
				continue
			}
			data, err := json.Marshal(cfg)
			if err != nil {
				return fmt.Errorf("database: encode output %q: %w", name, err)
			}
			version, err := s.nextVersion(ctx, tx)
			if err != nil {
				return err
			}
			query := "INSERT INTO falcosidekick_outputs (config, version, provisioned, updated_at, name) VALUES ({json}, ?, ?, ?, ?) " +
				"ON CONFLICT (name) DO UPDATE SET config = excluded.config, version = excluded.version, " +
				"provisioned = excluded.provisioned, updated_at = excluded.updated_at"
			if _, err := tx.ExecContext(ctx, s.dialect.q(query), string(data), version, true, now, name); err != nil {
				return fmt.Errorf("database: store output %q: %w", name, err)
			}
		}
		return nil
	})
}

// decodeConfig reads a stored config; integers come back as int64, without the precision a float64 loses.
func decodeConfig(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var cfg map[string]any
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return convertNumbers(cfg).(map[string]any), nil
}

func convertNumbers(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for k, item := range v {
			v[k] = convertNumbers(item)
		}
	case []any:
		for i, item := range v {
			v[i] = convertNumbers(item)
		}
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
		f, _ := v.Float64()
		return f
	}
	return value
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// readOutputs reads every output, or the named one.
func (s *SQL) readOutputs(ctx context.Context, q queryer, name string) (map[string]*core.OutputConfigEntry, error) {
	query := "SELECT name, config, version, provisioned, updated_at FROM falcosidekick_outputs"
	var args []any
	if name != "" {
		query += " WHERE name = ?"
		args = append(args, name)
	}
	rows, err := q.QueryContext(ctx, s.dialect.q(query), args...)
	if err != nil {
		return nil, fmt.Errorf("database: read outputs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make(map[string]*core.OutputConfigEntry)
	for rows.Next() {
		var (
			entry   core.OutputConfigEntry
			data    []byte
			updated int64
		)
		if err := rows.Scan(&entry.Name, &data, &entry.Version, &entry.Provisioned, &updated); err != nil {
			return nil, fmt.Errorf("database: read output: %w", err)
		}
		if entry.Config, err = decodeConfig(data); err != nil {
			return nil, fmt.Errorf("database: decode output %q: %w", entry.Name, err)
		}
		entry.UpdatedAt = time.Unix(0, updated).UTC()
		result[entry.Name] = &entry
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("database: read outputs: %w", err)
	}
	return result, nil
}

// GetOutputConfigs returns every stored output.
func (s *SQL) GetOutputConfigs(ctx context.Context) (map[string]*core.OutputConfigEntry, error) {
	return s.readOutputs(ctx, s.db, "")
}

// GetOutputConfig returns the named output, or nil and no error when it is not stored.
func (s *SQL) GetOutputConfig(ctx context.Context, name string) (*core.OutputConfigEntry, error) {
	stored, err := s.readOutputs(ctx, s.db, name)
	if err != nil {
		return nil, err
	}
	return stored[name], nil
}

// SaveOutputConfig stores cfg if the stored version is expected, keeping the provisioned flag.
func (s *SQL) SaveOutputConfig(ctx context.Context, name string, expected int64, cfg map[string]any) (int64, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return 0, fmt.Errorf("database: encode output %q: %w", name, err)
	}
	var version int64
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		if version, err = s.nextVersion(ctx, tx); err != nil {
			return err
		}
		now := time.Now().UnixNano()
		query := "UPDATE falcosidekick_outputs SET config = {json}, version = ?, updated_at = ? WHERE name = ? AND version = ?"
		args := []any{string(data), version, now, name, expected}
		if expected == 0 {
			query = "INSERT INTO falcosidekick_outputs (config, version, updated_at, name, provisioned) VALUES ({json}, ?, ?, ?, ?) " +
				"ON CONFLICT (name) DO NOTHING"
			args = []any{string(data), version, now, name, false}
		}
		if err := execOne(ctx, tx, s.dialect.q(query), args...); err != nil {
			return err
		}
		return s.notifyChange(ctx, tx, name)
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

// DeleteOutputConfig removes the entry if its version is expected; expected 0 means no entry.
func (s *SQL) DeleteOutputConfig(ctx context.Context, name string, expected int64) error {
	if expected == 0 {
		existing, err := s.readOutputs(ctx, s.db, name)
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			return core.ErrVersionConflict
		}
		return nil
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := execOne(ctx, tx, s.dialect.q("DELETE FROM falcosidekick_outputs WHERE name = ? AND version = ?"), name, expected); err != nil {
			return err
		}
		return s.notifyChange(ctx, tx, name)
	})
}

// execOne runs a conditional write; no row changed means the condition did not hold.
func execOne(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("database: write output: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("database: write output: %w", err)
	}
	if n == 0 {
		return core.ErrVersionConflict
	}
	return nil
}

// GetPipelineLayout returns the stored layout, or nil.
func (s *SQL) GetPipelineLayout(ctx context.Context) (*core.PipelineLayout, error) {
	var (
		data    []byte
		updated int64
	)
	err := s.db.QueryRowContext(ctx, "SELECT data, updated_at FROM falcosidekick_layout WHERE id = 1").Scan(&data, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("database: read layout: %w", err)
	}
	layout := &core.PipelineLayout{UpdatedAt: time.Unix(0, updated).UTC()}
	if err := json.Unmarshal(data, &layout.Nodes); err != nil {
		return nil, fmt.Errorf("database: decode layout: %w", err)
	}
	return layout, nil
}

// SavePipelineLayout stores the layout.
func (s *SQL) SavePipelineLayout(ctx context.Context, layout *core.PipelineLayout) error {
	data, err := json.Marshal(layout.Nodes)
	if err != nil {
		return fmt.Errorf("database: encode layout: %w", err)
	}
	query := "INSERT INTO falcosidekick_layout (id, data, updated_at) VALUES (1, {json}, ?) " +
		"ON CONFLICT (id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at"
	if _, err := s.db.ExecContext(ctx, s.dialect.q(query), string(data), time.Now().UnixNano()); err != nil {
		return fmt.Errorf("database: save layout: %w", err)
	}
	return nil
}

// Close closes the connection pool.
func (s *SQL) Close() error {
	return s.db.Close()
}
