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

//go:build e2e

package e2e

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// envRedisAddr is a comma-separated list of host:port, one per server version.
	envRedisAddr     = "FALCOSIDEKICK_E2E_REDIS_ADDR"
	envRedisPassword = "FALCOSIDEKICK_E2E_REDIS_PASSWORD"
)

type redisTarget struct {
	client   *goredis.Client
	addr     string
	password string
}

func redisTargets(t *testing.T) []redisTarget {
	t.Helper()
	addrs := requireEnv(t, envRedisAddr)
	password := requireEnv(t, envRedisPassword)
	var targets []redisTarget
	for addr := range strings.SplitSeq(addrs, ",") {
		addr = strings.TrimSpace(addr)
		client := goredis.NewClient(&goredis.Options{Addr: addr, Password: password})
		t.Cleanup(func() { _ = client.Close() })
		targets = append(targets, redisTarget{client: client, addr: addr, password: password})
	}
	return targets
}

func (r redisTarget) output(password, extra string) string {
	out := fmt.Sprintf("redis:\n  address: %q\n  password: %q\n", r.addr, password)
	for line := range strings.SplitSeq(strings.TrimRight(extra, "\n"), "\n") {
		if line != "" {
			out += "  " + line + "\n"
		}
	}
	return out
}

func redisKey(t *testing.T, target redisTarget, marker string) string {
	t.Helper()
	key := "fsk-e2e-" + marker
	t.Cleanup(func() { _ = target.client.Del(context.Background(), key).Err() })
	return key
}

func assertRedisEvent(t *testing.T, payload, marker string) string {
	t.Helper()
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(payload), &got))
	assert.Equal(t, "E2E "+marker, got["rule"])
	assert.Equal(t, "Warning", got["priority"])
	assert.Equal(t, marker, got["output_fields"].(map[string]any)["e2e.marker"])
	uuid, _ := got["uuid"].(string)
	assert.NotEmpty(t, uuid)
	return uuid
}

func TestRedisDeliversEvent(t *testing.T) {
	for _, target := range redisTargets(t) {
		version, err := target.client.Info(context.Background(), "server").Result()
		require.NoError(t, err)
		t.Logf("%s: %s", target.addr, firstLine(version, "redis_version:"))

		// "" leaves storage_type unset: the default is a stream.
		for _, storage := range []string{"list", "hash", "stream", ""} {
			t.Run(target.addr+"/"+cmp.Or(storage, "default"), func(t *testing.T) {
				marker := newMarker(t)
				key := redisKey(t, target, marker)
				extra := "key: " + key + "\n"
				if storage != "" {
					extra += "storage_type: " + storage + "\n"
				}
				sk := startSidekick(t, target.output(target.password, extra))
				sk.postEvent(t, marker)
				sk.waitStatus(t, "redis", func(st outputStatus) bool { return st.SentTotal == 1 })

				ctx := context.Background()
				switch storage {
				case "list":
					values, err := target.client.LRange(ctx, key, 0, -1).Result()
					require.NoError(t, err)
					require.Len(t, values, 1)
					assertRedisEvent(t, values[0], marker)
				case "hash":
					values, err := target.client.HGetAll(ctx, key).Result()
					require.NoError(t, err)
					require.Len(t, values, 1)
					for field, value := range values {
						assert.Equal(t, field, assertRedisEvent(t, value, marker), "field is the event UUID")
					}
				case "stream", "":
					entries, err := target.client.XRange(ctx, key, "-", "+").Result()
					require.NoError(t, err)
					require.Len(t, entries, 1)
					assertRedisEvent(t, entries[0].Values["event"].(string), marker)
				}

				st := sk.status(t, "redis")
				assert.Zero(t, st.FailedTotal)
				assert.NotContains(t, sk.logs.String(), target.password)
				assert.NotContains(t, outputConfig(t, sk, "redis"), target.password)
			})
		}
	}
}

func TestRedisBatchUsesOnePipeline(t *testing.T) {
	for _, target := range redisTargets(t) {
		t.Run(target.addr, func(t *testing.T) {
			marker := newMarker(t)
			key := redisKey(t, target, marker)
			sk := startSidekick(t, target.output(target.password,
				"key: "+key+"\nruntime:\n  batching:\n    enabled: true\n    batch_size: 2\n    flush_interval: 5s\n"))
			sk.postEvent(t, marker)
			sk.postEvent(t, marker)
			sk.waitStatus(t, "redis", func(st outputStatus) bool { return st.SentTotal == 2 })
			n, err := target.client.XLen(context.Background(), key).Result()
			require.NoError(t, err)
			assert.Equal(t, int64(2), n)
		})
	}
}

func TestRedisRefusesRemovedSettings(t *testing.T) {
	target := redisTarget{addr: "127.0.0.1:1", password: "unused"}
	for _, tc := range []struct{ name, extra, want string }{
		{name: "no key", extra: "", want: "key: is required"},
		{name: "hashmap", extra: "key: falco\nstorage_type: hashmap\n", want: "storage_type: must be stream/list/hash"},
		{name: "tls_enabled", extra: "key: falco\ntls_enabled: true\n", want: "unknown keys: tls_enabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Contains(t, startSidekickFails(t, target.output(target.password, tc.extra)), tc.want)
		})
	}
}

func TestRedisWrongPasswordStartsDegraded(t *testing.T) {
	for _, target := range redisTargets(t) {
		t.Run(target.addr, func(t *testing.T) {
			wrong := "wrong-" + newMarker(t)
			_, logs := startSidekickDegraded(t, "redis", target.output(wrong, "key: falco\n"))
			assert.Contains(t, logs, "health check")
			assert.Contains(t, logs, "WRONGPASS")
			assert.NotContains(t, logs, wrong)
		})
	}
}

func TestRedisReportsUnreachableServer(t *testing.T) {
	target := redisTarget{addr: fmt.Sprintf("127.0.0.1:%d", freePort(t)), password: "unused-" + newMarker(t)}
	sk := startSidekick(t, target.output(target.password, "key: falco\n"))
	st := sk.status(t, "redis")
	assert.Equal(t, "degraded", st.Status, "an unreachable server at startup is transient")
	assert.Contains(t, st.LastWarning, "connection refused")

	sk.postEvent(t, newMarker(t))
	st = sk.waitStatus(t, "redis", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Contains(t, st.LastError, "connection refused")
	assert.NotContains(t, sk.logs.String(), target.password)
}

func outputConfig(t *testing.T, sk *sidekick, name string) string {
	t.Helper()
	resp, err := httpDo(http.MethodGet, sk.apiURL+"/api/v1/pipeline/outputs/"+name, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func firstLine(text, prefix string) string {
	for line := range strings.SplitSeq(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
