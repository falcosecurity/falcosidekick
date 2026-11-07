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

package kafka

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

// syncBuffer is a bytes.Buffer safe for the client goroutines that log.
type syncBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestInitAcceptsEveryAcksMode(t *testing.T) {
	for _, acks := range []string{"", "all", "one", "none"} {
		for _, async := range []bool{false, true} {
			t.Run(fmt.Sprintf("%q async=%t", acks, async), func(t *testing.T) {
				d, err := createOutput(map[string]any{
					"brokers":  []string{"127.0.0.1:1"},
					"topic":    "falco",
					"producer": map[string]any{"required_acks": acks, "async": async},
				}, output.Deps{})
				require.NoError(t, err)
				require.NoError(t, d.Init(context.Background()))
				drv := d.(*driver)
				assert.Equal(t, resolveACKs(acks), drv.client.OptValue(kgo.RequiredAcks))
				wantIdempotent := acks == "" || acks == "all"
				assert.Equal(t, !wantIdempotent, drv.client.OptValue(kgo.DisableIdempotentWrite))
				drv.client.Close()
			})
		}
	}
}

func TestClientLoggerLevel(t *testing.T) {
	assert.Equal(t, kgo.LogLevelWarn, clientLogger{}.Level())
}

func TestClientLoggerMapsLevelsAndAttributes(t *testing.T) {
	for _, tc := range []struct {
		want  string
		level kgo.LogLevel
	}{
		{level: kgo.LogLevelError, want: "ERROR"},
		{level: kgo.LogLevelWarn, want: "WARN"},
		{level: kgo.LogLevelInfo, want: "INFO"},
		{level: kgo.LogLevelDebug, want: "DEBUG"},
		{level: kgo.LogLevelNone, want: "DEBUG"},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			clientLogger{logger: logger}.Log(tc.level, "unable to open connection to broker", "addr", "127.0.0.1:1", "broker", 3)

			var record map[string]any
			require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
			assert.Equal(t, tc.want, record["level"])
			assert.Equal(t, "unable to open connection to broker", record["msg"])
			assert.Equal(t, "127.0.0.1:1", record["addr"])
			assert.EqualValues(t, 3, record["broker"])
		})
	}
}

func TestClientLoggerKeepsOnlyIdentifyingFields(t *testing.T) {
	const sentinel = "BROKER_TEXT_SENTINEL"
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	clientLogger{logger: logger}.Log(kgo.LogLevelError, "produce failed",
		"topic", "events", "partition", int32(2), "err", errors.New(sentinel), "req", sentinel, "skipped", 3, "dangling")

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
	assert.Equal(t, "events", record["topic"])
	assert.EqualValues(t, 2, record["partition"])
	assert.Equal(t, "kafka client: request failed", record["err"])
	assert.NotContains(t, record, "req")
	assert.NotContains(t, record, "skipped")
	assert.NotContains(t, buf.String(), sentinel)
}

func TestClientLogsDialFailureWithoutSecrets(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	const password = "SASL_PASSWORD_SECRET"
	var logs syncBuffer
	d, err := createOutput(map[string]any{
		"brokers":  []string{addr},
		"topic":    "falco",
		"auth":     map[string]any{"sasl": "scram_sha512", "username": "user", "password": password},
		"producer": map[string]any{"delivery_timeout": "1s"},
	}, output.Deps{Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	require.NoError(t, err)
	require.NoError(t, d.Init(context.Background()))
	t.Cleanup(func() { _ = d.Close() })

	require.Error(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	out := logs.String()
	assert.Contains(t, out, "unable to open connection to broker")
	assert.Contains(t, out, "connection refused")
	assert.Contains(t, out, "output=kafka")
	assert.NotContains(t, out, password)
	assert.False(t, strings.Contains(out, "level=DEBUG") || strings.Contains(out, "level=INFO"), "only warnings and errors are forwarded:\n%s", out)
}
