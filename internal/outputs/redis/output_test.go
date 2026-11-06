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

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

const secret = "s3cr3t-redis-password"

func newDriver(t *testing.T, raw map[string]any) *driver {
	t.Helper()
	drv, err := OutputType.New(raw, output.Deps{})
	require.NoError(t, err)
	d := drv.(*driver)
	require.NoError(t, d.Init(context.Background()))
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		raw  map[string]any
		name string
		want string
	}{
		{name: "missing address", raw: map[string]any{}, want: "address: is required"},
		{name: "address with scheme", raw: map[string]any{"address": "redis://r:6379"}, want: "address"},
		{name: "address without port", raw: map[string]any{"address": "redis"}, want: "address"},
		{name: "port out of range", raw: map[string]any{"address": "r:70000"}, want: "port must be between"},
		{name: "negative database", raw: map[string]any{"address": "r:6379", "database": -1}, want: "database: must be 0 or greater"},
		{name: "unknown storage", raw: map[string]any{"address": "r:6379", "storage_type": "set"}, want: "storage_type"},
		{name: "empty key", raw: map[string]any{"address": "r:6379", "key": ""}, want: "key: is required"},
		{name: "username without password", raw: map[string]any{"address": "r:6379", "username": "u"}, want: "password: is required"},
		{name: "cert without key", raw: map[string]any{"address": "r:6379", "tls": map[string]any{"cert_file": "/x"}}, want: "tls"},
		{name: "unknown key", raw: map[string]any{"address": "r:6379", "storagetype": "list"}, want: "unknown keys"},
		{name: "database type", raw: map[string]any{"address": "r:6379", "database": "zero"}, want: "database"},
		{name: "negative max_len", raw: map[string]any{"address": "r:6379", "storage_type": "stream", "max_len": -1}, want: "max_len: must be 0 or greater"},
		{name: "max_len on list", raw: map[string]any{"address": "r:6379", "max_len": 10}, want: "max_len: applies only to storage_type stream"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.raw
			raw["password"] = secret
			if tt.name == "username without password" {
				delete(raw, "password")
			}
			_, err := OutputType.New(raw, output.Deps{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.NotContains(t, err.Error(), secret)
		})
	}
}

func TestDefaultsAndSchema(t *testing.T) {
	d := newDriver(t, map[string]any{"address": "127.0.0.1:6379", "runtime": map[string]any{"minimum_priority": "warning"}})
	assert.Equal(t, storageList, d.cfg.StorageType)
	assert.Equal(t, defaultKey, d.cfg.Key)
	assert.Equal(t, "redis", d.Name())
	assert.Equal(t, event.PriorityWarning, d.RuntimeConfig().MinPriority)
	assert.Equal(t, -1, d.opts.MaxRetries)
	assert.True(t, d.opts.ContextTimeoutEnabled)
	assert.Nil(t, d.opts.TLSConfig)

	secrets := map[string]bool{}
	for _, f := range OutputType.Schema.Fields {
		secrets[f.Name] = f.Secret
	}
	assert.True(t, secrets["password"])
	assert.False(t, secrets["username"])
	assert.Contains(t, secrets, "tls.ca_file")
	assert.Contains(t, secrets, "runtime.minimum_priority")
}

func TestTLSEnabledBuildsConfig(t *testing.T) {
	d := newDriver(t, map[string]any{
		"address": "r:6379", "tls_enabled": true,
		"tls": map[string]any{"server_name": "redis.internal"},
	})
	require.NotNil(t, d.opts.TLSConfig)
	assert.Equal(t, "redis.internal", d.opts.TLSConfig.ServerName)
}

func TestSendStorageTypes(t *testing.T) {
	evt := testutil.CreateValidEvent()
	tests := []struct {
		check   func(t *testing.T, cmd []string)
		storage string
	}{
		{storage: storageList, check: func(t *testing.T, cmd []string) {
			require.Len(t, cmd, 3)
			assert.Equal(t, []string{"RPUSH", "falco-events"}, cmd[:2])
			assertEventJSON(t, cmd[2])
		}},
		{storage: storageHashmap, check: func(t *testing.T, cmd []string) {
			require.Len(t, cmd, 4)
			assert.Equal(t, []string{"HSET", "falco-events", evt.UUID}, cmd[:3])
			assertEventJSON(t, cmd[3])
		}},
		{storage: storageStream, check: func(t *testing.T, cmd []string) {
			require.Len(t, cmd, 5)
			assert.Equal(t, []string{"XADD", "falco-events", "*", "event"}, cmd[:4])
			assertEventJSON(t, cmd[4])
		}},
	}
	for _, tt := range tests {
		t.Run(tt.storage, func(t *testing.T) {
			fake := startFakeRedis(t, secret)
			d := newDriver(t, map[string]any{
				"address": fake.addr, "password": secret, "database": 3,
				"storage_type": tt.storage, "key": "falco-events",
			})
			require.NoError(t, d.Send(context.Background(), evt))
			data := fake.data()
			require.Len(t, data, 1)
			tt.check(t, data[0])
			assert.Contains(t, fake.received(), []string{"SELECT", "3"})
		})
	}
}

func TestStreamMaxLen(t *testing.T) {
	fake := startFakeRedis(t, "")
	d := newDriver(t, map[string]any{"address": fake.addr, "storage_type": "stream", "max_len": 1000})
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	data := fake.data()
	require.Len(t, data, 1)
	assert.Equal(t, []string{"XADD", "falco", "maxlen", "~", "1000", "*", "event"}, data[0][:7])
}

func assertEventJSON(t *testing.T, payload string) {
	t.Helper()
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(payload), &got))
	assert.Equal(t, "Write below binary dir", got["rule"])
	assert.Equal(t, "error", got["priority"])
	assert.Equal(t, "test-uuid-001", got["uuid"])
	assert.Equal(t, "/bin/hack", got["output_fields"].(map[string]any)["fd.name"])
}

func TestSendBatchUsesOnePipeline(t *testing.T) {
	fake := startFakeRedis(t, "")
	d := newDriver(t, map[string]any{"address": fake.addr})
	first, second := testutil.CreateValidEvent(), testutil.CreateValidEvent()
	second.Rule = "second"
	require.NoError(t, d.SendBatch(context.Background(), []*event.Event{first, second}))
	data := fake.data()
	require.Len(t, data, 2)
	assert.Equal(t, "RPUSH", data[0][0])
	assert.Contains(t, data[1][2], `"rule":"second"`)
}

func TestSendReportsCommandError(t *testing.T) {
	fake := startFakeRedis(t, "")
	fake.reply("RPUSH", "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n")
	d := newDriver(t, map[string]any{"address": fake.addr})
	err := d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis send: WRONGTYPE")

	err = d.SendBatch(context.Background(), []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WRONGTYPE")
}

func TestSendMarshalError(t *testing.T) {
	d := newDriver(t, map[string]any{"address": "127.0.0.1:1"})
	evt := testutil.CreateValidEvent()
	evt.OutputFields["bad"] = make(chan int)
	err := d.Send(context.Background(), evt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis marshal")
}

func TestNotReadyBeforeInit(t *testing.T) {
	drv, err := OutputType.New(map[string]any{"address": "127.0.0.1:6379"}, output.Deps{})
	require.NoError(t, err)
	assert.ErrorIs(t, drv.Send(context.Background(), testutil.CreateValidEvent()), core.ErrNotReady)
	assert.ErrorIs(t, drv.HealthCheck(context.Background()), core.ErrNotReady)
	assert.NoError(t, drv.Close())
}

func TestHealthCheckClassification(t *testing.T) {
	tests := []struct {
		setup         func(f *fakeRedis)
		raw           map[string]any
		name          string
		misconfigured bool
		healthy       bool
	}{
		{name: "pong", healthy: true, raw: map[string]any{"password": secret}},
		{name: "wrong password", misconfigured: true, raw: map[string]any{"username": "falco", "password": "wrong-" + secret}},
		{name: "no auth", misconfigured: true, setup: func(f *fakeRedis) { f.reply("PING", "-NOAUTH Authentication required.\r\n") }},
		{name: "no permission", misconfigured: true, raw: map[string]any{"password": secret},
			setup: func(f *fakeRedis) {
				f.reply("PING", "-NOPERM User falco has no permissions to run the 'ping' command\r\n")
			}},
		{name: "password without server password", misconfigured: true, raw: map[string]any{"password": secret},
			setup: func(f *fakeRedis) {
				f.reply("AUTH", "-ERR AUTH <password> called without any password configured for the default user.\r\n")
			}},
		{name: "database out of range", misconfigured: true, raw: map[string]any{"password": secret, "database": 99}},
		{name: "loading is transient", raw: map[string]any{"password": secret},
			setup: func(f *fakeRedis) {
				f.reply("PING", "-LOADING Redis is loading the dataset in memory\r\n")
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := startFakeRedis(t, secret)
			if tt.setup != nil {
				tt.setup(fake)
			}
			raw := map[string]any{"address": fake.addr}
			for k, v := range tt.raw {
				raw[k] = v
			}
			err := newDriver(t, raw).HealthCheck(context.Background())
			if tt.healthy {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.misconfigured, errors.Is(err, output.ErrMisconfigured), err.Error())
			assert.NotContains(t, err.Error(), secret)
		})
	}
}

func TestSendErrorPermanence(t *testing.T) {
	tests := []struct {
		reply     string
		name      string
		permanent bool
	}{
		{name: "wrong type", reply: "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n", permanent: true},
		{name: "no permission", reply: "-NOPERM User falco has no permissions to run the 'rpush' command\r\n", permanent: true},
		{name: "loading", reply: "-LOADING Redis is loading the dataset in memory\r\n"},
		{name: "read only replica", reply: "-READONLY You can't write against a read only replica.\r\n"},
		{name: "out of memory", reply: "-OOM command not allowed when used memory > 'maxmemory'.\r\n"},
		{name: "try again", reply: "-TRYAGAIN Multiple keys request during rehashing of slot\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := startFakeRedis(t, secret)
			fake.reply("RPUSH", tt.reply)
			err := newDriver(t, map[string]any{"address": fake.addr, "password": secret}).Send(context.Background(), testutil.CreateValidEvent())
			require.Error(t, err)
			assert.Equal(t, tt.permanent, output.IsPermanent(err), err.Error())
		})
	}
}

// A proxy or server may echo submitted values in its error replies.
func TestErrorsNeverCopyServerText(t *testing.T) {
	const echoed = "echoed-by-server"
	for _, tt := range []struct {
		command string
		reply   string
		want    string
		probe   bool
	}{
		{command: "RPUSH", reply: "-WRONGTYPE value " + echoed + "\r\n", want: "redis send: WRONGTYPE"},
		{command: "RPUSH", reply: "-" + echoed + " unknown prefix\r\n", want: "redis send: server error"},
		{command: "PING", reply: "-NOPERM user " + echoed + " has no permissions\r\n", want: "redis healthcheck: NOPERM", probe: true},
		{command: "PING", reply: "-ERR " + echoed + "\r\n", want: "redis healthcheck: ERR", probe: true},
	} {
		t.Run(tt.reply, func(t *testing.T) {
			fake := startFakeRedis(t, secret)
			fake.reply(tt.command, tt.reply)
			d := newDriver(t, map[string]any{"address": fake.addr, "password": secret})
			var err error
			if tt.probe {
				err = d.HealthCheck(context.Background())
			} else {
				err = d.Send(context.Background(), testutil.CreateValidEvent())
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.NotContains(t, fmt.Sprintf("%v %+v %q", err, err, err), echoed)
		})
	}
}

func TestHealthCheckUnreachableIsTransient(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	err = newDriver(t, map[string]any{"address": addr, "password": secret}).HealthCheck(context.Background())
	require.Error(t, err)
	assert.NotErrorIs(t, err, output.ErrMisconfigured)
	assert.Contains(t, err.Error(), "connection refused")
	assert.NotContains(t, err.Error(), secret)
}

func TestHealthCheckUntrustedCertificateIsMisconfiguration(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	addr := strings.TrimPrefix(server.URL, "https://")

	err := newDriver(t, map[string]any{"address": addr, "tls_enabled": true}).HealthCheck(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, output.ErrMisconfigured)
}

func TestReturnsWhenContextEndsOnSilentServer(t *testing.T) {
	addr := testutil.HangingTCPServer(t)
	d := newDriver(t, map[string]any{"address": addr, "password": secret})
	calls := map[string]func(context.Context) error{
		"Send": func(ctx context.Context) error { return d.Send(ctx, testutil.CreateValidEvent()) },
		"SendBatch": func(ctx context.Context) error {
			return d.SendBatch(ctx, []*event.Event{testutil.CreateValidEvent(), testutil.CreateValidEvent()})
		},
		"HealthCheck": d.HealthCheck,
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.NotContains(t, testutil.RequireReturnsOnCancel(t, name, call).Error(), secret)
		})
	}
}

func TestCloseAfterInit(t *testing.T) {
	drv, err := OutputType.New(map[string]any{"address": "127.0.0.1:6379"}, output.Deps{})
	require.NoError(t, err)
	require.NoError(t, drv.Init(context.Background()))
	require.NoError(t, drv.Close())
	err = drv.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), name+" send: ")
}
