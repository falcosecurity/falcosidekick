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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

func TestDialectPlaceholders(t *testing.T) {
	query := "UPDATE t SET a = {json}, b = ? WHERE c = ?"
	assert.Equal(t, "UPDATE t SET a = ?, b = ? WHERE c = ?", sqliteDialect.q(query))
	assert.Equal(t, "UPDATE t SET a = CAST($1 AS JSONB), b = $2 WHERE c = $3", postgresDialect.q(query))
}

func TestOpenSQLiteKeepsTheDataAndCreatesPrivateFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sidekick.db")
	s, err := OpenSQLite(t.Context(), path)
	require.NoError(t, err)
	version, err := s.SaveOutputConfig(t.Context(), "webhook", 0, map[string]any{"token_file": "/run/secrets/t"})
	require.NoError(t, err)
	require.NoError(t, s.SavePipelineLayout(t.Context(), &core.PipelineLayout{Nodes: []core.LayoutNode{{ID: "a"}}}))

	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(name)
		require.NoError(t, err, name)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), name)
	}
	require.NoError(t, s.Close())

	reopened, err := OpenSQLite(t.Context(), path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	entry, err := reopened.GetOutputConfig(t.Context(), "webhook")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, version, entry.Version)
	assert.Equal(t, map[string]any{"token_file": "/run/secrets/t"}, entry.Config)
	layout, err := reopened.GetPipelineLayout(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []core.LayoutNode{{ID: "a"}}, layout.Nodes)
	next, err := reopened.SaveOutputConfig(t.Context(), "slack", 0, map[string]any{})
	require.NoError(t, err)
	assert.Greater(t, next, version, "the version sequence survives a restart")
}

func TestOpenSQLiteRefusesBadPaths(t *testing.T) {
	for _, path := range []string{"", "db?mode=memory", "db#x", filepath.Join(t.TempDir(), "missing", "sidekick.db")} {
		_, err := OpenSQLite(t.Context(), path)
		assert.Error(t, err, path)
	}
}

// A database migrated by a newer Sidekick is refused, and left as it is.
func TestOpenSQLiteRefusesANewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sidekick.db")
	s, err := OpenSQLite(t.Context(), path)
	require.NoError(t, err)
	_, err = s.db.ExecContext(t.Context(), "INSERT INTO falcosidekick_schema (version) VALUES (99)")
	require.NoError(t, err)
	require.NoError(t, s.Close())

	_, err = OpenSQLite(t.Context(), path)
	require.ErrorContains(t, err, "schema version 99 is newer than this Sidekick")
}

// Writers racing on one output: exactly one create wins, the others get a conflict.
func TestSQLConcurrentCreatesHaveOneWinner(t *testing.T) {
	stores := map[string]openStore{
		"sqlite": func(t *testing.T) core.Database {
			s, err := OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "sidekick.db"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })
			return s
		},
		"postgres": openPostgresSchema,
	}
	for name, open := range stores {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			var (
				wg        sync.WaitGroup
				mu        sync.Mutex
				wins      int
				conflicts int
			)
			for i := range 16 {
				wg.Go(func() {
					_, err := s.SaveOutputConfig(context.Background(), "webhook", 0, map[string]any{"writer": i})
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						wins++
					case errors.Is(err, core.ErrVersionConflict):
						conflicts++
					default:
						t.Errorf("unexpected error: %v", err)
					}
				})
			}
			wg.Wait()
			assert.Equal(t, 1, wins)
			assert.Equal(t, 15, conflicts)
		})
	}
}

// Instances started together on an empty database migrate it once.
func TestOpenPostgresConcurrentFirstStartMigratesOnce(t *testing.T) {
	cfg := postgresConfig(t, newPostgresSchema(t))

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Go(func() {
			s, err := OpenPostgres(context.Background(), cfg.Copy(), 2)
			if err == nil {
				_ = s.Close()
			}
			errs[i] = err
		})
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	s, err := OpenPostgres(t.Context(), cfg.Copy(), 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	var applied int
	require.NoError(t, s.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM falcosidekick_schema").Scan(&applied))
	assert.Equal(t, 1, applied)
}

// otherReplica opens a raw connection on the schema s uses, standing in for another instance.
func otherReplica(t *testing.T, s *SQL) *sql.DB {
	t.Helper()
	var schema string
	require.NoError(t, s.db.QueryRowContext(t.Context(), "SELECT current_schema()").Scan(&schema))
	db := stdlib.OpenDB(*postgresConfig(t, schema))
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// waitForLockWait blocks until a backend running a statement that starts with prefix waits on a lock.
func waitForLockWait(t *testing.T, db *sql.DB, prefix string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var n int
		err := db.QueryRowContext(t.Context(),
			"SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE $1", prefix+"%").Scan(&n)
		return err == nil && n > 0
	}, 10*time.Second, 20*time.Millisecond, "no backend waiting on a lock for %q", prefix)
}

// An API delete from another instance commits while Provision waits to write the same output.
func TestPostgresProvisionStoresAFileOutputDeletedMeanwhile(t *testing.T) {
	s := openPostgresSchema(t).(*SQL)
	ctx := t.Context()
	version, err := s.SaveOutputConfig(ctx, "slack", 0, map[string]any{"channel": "api"})
	require.NoError(t, err)
	other := otherReplica(t, s)
	tx, err := other.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "SELECT 1 FROM falcosidekick_outputs WHERE name = 'slack' FOR UPDATE")
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- s.Provision(context.Background(), &core.ProvisionRequest{Outputs: map[string]map[string]any{"slack": {"channel": "file"}}})
	}()
	waitForLockWait(t, other, "INSERT INTO falcosidekick_outputs")
	_, err = tx.ExecContext(ctx, "DELETE FROM falcosidekick_outputs WHERE name = $1 AND version = $2", "slack", version)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	require.NoError(t, <-done)
	entry, err := s.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	require.NotNil(t, entry, "the files define slack")
	assert.True(t, entry.Provisioned)
	assert.Equal(t, "file", entry.Config["channel"])
}

// An API create from another instance commits while Provision waits to write the same name.
func TestPostgresProvisionWinsAConcurrentCreate(t *testing.T) {
	s := openPostgresSchema(t).(*SQL)
	ctx := t.Context()
	other := otherReplica(t, s)
	tx, err := other.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "INSERT INTO falcosidekick_outputs (config, version, updated_at, name, provisioned) "+
		"VALUES (CAST($1 AS JSONB), $2, $3, $4, $5) ON CONFLICT (name) DO NOTHING", `{"channel":"api"}`, 1000, 0, "slack", false)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- s.Provision(context.Background(), &core.ProvisionRequest{Outputs: map[string]map[string]any{"slack": {"channel": "file"}}})
	}()
	waitForLockWait(t, other, "INSERT INTO falcosidekick_outputs")
	require.NoError(t, tx.Commit())

	require.NoError(t, <-done)
	entry, err := s.GetOutputConfig(ctx, "slack")
	require.NoError(t, err)
	assert.Equal(t, "file", entry.Config["channel"])
	assert.True(t, entry.Provisioned)
}

// Instances provisioning together on a server whose default isolation is repeatable read all succeed.
func TestPostgresConcurrentProvisionIgnoresTheServerDefaultIsolation(t *testing.T) {
	cfg := postgresConfig(t, newPostgresSchema(t))
	cfg.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	s, err := OpenPostgres(t.Context(), cfg, 8)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			errs[i] = s.Provision(context.Background(), &core.ProvisionRequest{Outputs: map[string]map[string]any{"slack": {"channel": "file"}}})
		})
	}
	wg.Wait()
	for i, err := range errs {
		assert.NoError(t, err, "instance %d", i)
	}
}

// Names sqlite reads specially are ordinary files once the path is absolute.
func TestOpenSQLiteTreatsSpecialNamesAsFiles(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, name := range []string{":memory:", "file:sidekick.db"} {
		s, err := OpenSQLite(t.Context(), name)
		require.NoError(t, err, name)
		_, err = s.SaveOutputConfig(t.Context(), "slack", 0, map[string]any{"a": 1})
		require.NoError(t, err)
		require.NoError(t, s.Close())

		reopened, err := OpenSQLite(t.Context(), name)
		require.NoError(t, err)
		entry, err := reopened.GetOutputConfig(t.Context(), "slack")
		require.NoError(t, err)
		assert.NotNil(t, entry, "%s keeps its data", name)
		require.NoError(t, reopened.Close())
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	_, err := os.Stat(filepath.Join(dir, "sidekick.db"))
	assert.True(t, os.IsNotExist(err), "no database is opened under another name")
}

// A commit the server refused is a definite failure; a commit lost on the way may have been applied.
func TestPostgresCommitOutcome(t *testing.T) {
	assert.False(t, postgresDialect.commitUnknown(&pgconn.PgError{Code: "40001"}))
	assert.True(t, postgresDialect.commitUnknown(errors.New("unexpected EOF")))
	assert.Nil(t, sqliteDialect.commitUnknown, "a local file commit is never uncertain")
}
