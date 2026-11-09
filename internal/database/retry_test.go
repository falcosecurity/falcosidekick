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
	"database/sql/driver"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pingScript is a database/sql driver whose pings return the queued errors, then nil.
type pingScript struct {
	errs  []error
	mu    sync.Mutex
	pings int
}

func (s *pingScript) Open(string) (driver.Conn, error) { return scriptConn{s}, nil }

type scriptConn struct{ s *pingScript }

func (c scriptConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }

func (c scriptConn) Close() error { return nil }

func (c scriptConn) Begin() (driver.Tx, error) { return nil, errors.New("not used") }

func (c scriptConn) Ping(context.Context) error {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.s.pings++
	if len(c.s.errs) == 0 {
		return nil
	}
	err := c.s.errs[0]
	c.s.errs = c.s.errs[1:]
	return err
}

var scriptCount int

func scriptDB(t *testing.T, errs ...error) (*sql.DB, *pingScript) {
	t.Helper()
	s := &pingScript{errs: errs}
	scriptCount++
	name := fmt.Sprintf("ping-script-%d", scriptCount)
	sql.Register(name, s)
	db, err := sql.Open(name, "")
	require.NoError(t, err)
	db.SetMaxIdleConns(0)
	t.Cleanup(func() { _ = db.Close() })
	return db, s
}

var errRefused = fmt.Errorf("dial tcp 10.0.0.1:5432: connect: %w", syscall.ECONNREFUSED)

// A database that starts together with Sidekick refuses connections for a while; Sidekick waits.
func TestPingWaitsForADatabaseStillStarting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db, s := scriptDB(t, errRefused, errRefused, errRefused)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		start := time.Now()
		require.NoError(t, pingUntilReady(ctx, db))
		assert.Equal(t, 4, s.pings)
		assert.Equal(t, 250*time.Millisecond+500*time.Millisecond+time.Second, time.Since(start), "backoff doubles")
	})
}

// Waiting is bounded by connect_timeout; then startup fails with the last cause.
func TestPingGivesUpAtTheTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		errs := make([]error, 100)
		for i := range errs {
			errs[i] = errRefused
		}
		db, _ := scriptDB(t, errs...)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		start := time.Now()
		err := pingUntilReady(ctx, db)
		require.Error(t, err)
		assert.ErrorIs(t, err, syscall.ECONNREFUSED)
		assert.Equal(t, 30*time.Second, time.Since(start), "no wait beyond connect_timeout")
	})
}

// The backoff stops growing at 5s.
func TestPingBackoffIsCapped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		errs := make([]error, 8)
		for i := range errs {
			errs[i] = errRefused
		}
		db, s := scriptDB(t, errs...)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		start := time.Now()
		require.NoError(t, pingUntilReady(ctx, db))
		assert.Equal(t, 9, s.pings)
		// 0.25 + 0.5 + 1 + 2 + 4, then 5 three times.
		assert.Equal(t, 7750*time.Millisecond+15*time.Second, time.Since(start))
	})
}

// A reply from postgres itself, such as a refused password, cannot change by waiting.
func TestPingFailsAtOnceWhenPostgresAnswers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db, s := scriptDB(t, &pgconn.PgError{Code: "28P01", Message: "password authentication failed"})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		start := time.Now()
		err := pingUntilReady(ctx, db)
		require.Error(t, err)
		assert.Equal(t, 1, s.pings)
		assert.Zero(t, time.Since(start))
	})
}

func TestErrorClassNamesTheCauseOnly(t *testing.T) {
	assert.Equal(t, "connection refused", errorClass(errRefused))
	assert.Equal(t, "unreachable", errorClass(errors.New("postgres://user:secret@db: boom")))
}
