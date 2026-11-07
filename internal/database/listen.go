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
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	listenRetryMin = time.Second
	listenRetryMax = 30 * time.Second
)

// ListenOutputChanges calls changed when another instance changes an output, until ctx ends. It
// holds its own connection, outside the pool. changed is also called each time the connection is
// (re)established, after LISTEN, since notifications sent while it was down are lost.
func ListenOutputChanges(ctx context.Context, settings *pgx.ConnConfig, changed func(), logger *slog.Logger) {
	retry := listenRetryMin
	for ctx.Err() == nil {
		listening, err := listenOnce(ctx, settings, changed)
		if ctx.Err() != nil {
			return
		}
		if listening {
			retry = listenRetryMin
		}
		logger.Warn("database: change notifications lost, reconnecting", "error", err, "retry_in", retry)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(2*retry, listenRetryMax)
	}
}

// listenOnce listens on one connection until it fails; listening reports whether LISTEN succeeded.
func listenOnce(ctx context.Context, settings *pgx.ConnConfig, changed func()) (listening bool, err error) {
	conn, err := pgx.ConnectConfig(ctx, settings.Copy())
	if err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()
	if _, err := conn.Exec(ctx, "LISTEN "+OutputsChannel); err != nil {
		return false, fmt.Errorf("listen: %w", err)
	}
	changed()
	for {
		if _, err := conn.WaitForNotification(ctx); err != nil {
			return true, err
		}
		changed()
	}
}
