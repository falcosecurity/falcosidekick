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
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Writes notify the listeners; a dropped listener connection reconnects and calls changed again.
func TestListenOutputChanges(t *testing.T) {
	cfg := postgresConfig(t, newPostgresSchema(t))
	s, err := OpenPostgres(t.Context(), cfg.Copy(), 2)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ListenOutputChanges(ctx, cfg, func() { calls.Add(1) }, slog.Default())
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	require.Eventually(t, func() bool { return calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond, "changed after LISTEN")

	version, err := s.SaveOutputConfig(t.Context(), "slack", 0, map[string]any{"v": 1})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return calls.Load() == 2 }, 5*time.Second, 10*time.Millisecond, "a create notifies")
	_, err = s.SaveOutputConfig(t.Context(), "slack", version+100, map[string]any{"v": 2})
	require.Error(t, err)
	require.NoError(t, s.DeleteOutputConfig(t.Context(), "slack", version))
	require.Eventually(t, func() bool { return calls.Load() == 3 }, 5*time.Second, 10*time.Millisecond, "a delete notifies, a refused write does not")

	admin := stdlib.OpenDB(*postgresConfig(t, ""))
	t.Cleanup(func() { _ = admin.Close() })
	_, err = admin.ExecContext(t.Context(),
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE 'LISTEN %' AND datname = current_database() AND pid <> pg_backend_pid()")
	require.NoError(t, err)
	require.Eventually(t, func() bool { return calls.Load() >= 4 }, 10*time.Second, 20*time.Millisecond, "reconnects and reconciles")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the listener did not stop with its context")
	}
	assert.GreaterOrEqual(t, calls.Load(), int32(4))
}
