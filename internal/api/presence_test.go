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

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/inmemory"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
)

func webhookRig(t *testing.T, stored map[string]any) (*mutationTestRig, *database.Memory) {
	t.Helper()
	cat, err := catalog.New([]output.Type{webhook.OutputType})
	require.NoError(t, err)
	db := database.NewMemory()
	if stored != nil {
		seedOutput(t, db, "webhook", stored)
	}
	return buildMutationRig(t, db, cat, true), db
}

// UseNumber keeps the number as written, so nothing is truncated or saturated before the field check.
func TestPutRefusesNumbersOutsideTheirField(t *testing.T) {
	for _, tt := range []struct {
		runtime string
		want    string
	}{
		{`{"workers":99999999999999999999}`, "runtime.workers: is out of range"},
		{`{"workers":1e20}`, "runtime.workers: is out of range"},
		{`{"queue_size":1.9}`, "runtime.queue_size: must be an integer"},
		{`{"queue_size":100001}`, "runtime.queue_size: must be an integer between 1 and 100000"},
		{`{"workers":0}`, "runtime.workers: must be an integer between 1 and 256"},
		{`{"workers":true}`, "runtime.workers: must be an integer"},
		{`{"health_check":2}`, "runtime.health_check: must be true or false"},
		{`{"health_check":1}`, "runtime.health_check: must be true or false"},
		{`{"batching":{"enabled":0}}`, "runtime.batching.enabled: must be true or false"},
		{`{"retry":{"initial_interval":30}}`, "runtime.retry.initial_interval: must be a duration such as 30s or 1m"},
		{`{"retry":{"multiplier":11}}`, "runtime.retry.multiplier: must be a number between 1 and 10"},
		{`{"retry":{"initial_interval":"0s"}}`, "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{`{"retry":{"initial_interval":0}}`, "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{`{"retry":{"max_interval":0}}`, "runtime.retry.max_interval: must be a duration between 1ms and 1h"},
		{`{"circuit_breaker":{"reset_timeout":0}}`, "runtime.circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
		{`{"circuit_breaker":{"reset_timeout":"0s"}}`, "runtime.circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
	} {
		t.Run(tt.runtime, func(t *testing.T) {
			rig, db := webhookRig(t, nil)
			body := `{"version":0,"config":{"host":"http://127.0.0.1:1","runtime":` + tt.runtime + `}}`
			raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook", body, http.StatusBadRequest)
			assert.Contains(t, string(raw), tt.want)
			assert.NotContains(t, string(raw), "makechan")
			stored, err := db.GetOutputConfig(t.Context(), "webhook")
			require.NoError(t, err)
			assert.Nil(t, stored, "nothing is stored")
			assert.Empty(t, rig.Server.pipeline.CollectOutputStatus(), "nothing is started")
		})
	}
}

// The integer 0 is "0s": stored as written where the field allows it, refused with the range where a minimum applies.
func TestPutReadsAZeroDurationAsTheFilesDo(t *testing.T) {
	for _, tt := range []struct {
		stored any
		ttl    string
	}{
		{ttl: `0`, stored: json.Number("0")},
		{ttl: `"0s"`, stored: "0s"},
	} {
		t.Run(tt.ttl, func(t *testing.T) {
			cat, err := catalog.New([]output.Type{inmemory.OutputType})
			require.NoError(t, err)
			db := database.NewMemory()
			rig := buildMutationRig(t, db, cat, true)
			body := `{"version":0,"config":{"capacity":10,"ttl":` + tt.ttl + `}}`
			requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/inmemory", body, http.StatusOK)
			stored, err := db.GetOutputConfig(t.Context(), "inmemory")
			require.NoError(t, err)
			require.NotNil(t, stored)
			assert.Equal(t, tt.stored, stored.Config["ttl"], "stored as written")
			assert.Len(t, rig.Server.pipeline.CollectOutputStatus(), 1, "the output is started")
		})
	}
}

func TestPutStoresExactNumbers(t *testing.T) {
	rig, db := webhookRig(t, nil)
	body := `{"version":0,"config":{"host":"http://127.0.0.1:1","runtime":{"health_check":false,"workers":256,"queue_size":100000,"retry":{"multiplier":1.5}}}}`
	requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook", body, http.StatusOK)
	stored, err := db.GetOutputConfig(t.Context(), "webhook")
	require.NoError(t, err)
	require.NotNil(t, stored)
	runtime, _ := stored.Config["runtime"].(map[string]any)
	assert.Equal(t, json.Number("256"), runtime["workers"])
	assert.Equal(t, json.Number("100000"), runtime["queue_size"])
	assert.Equal(t, map[string]any{"multiplier": json.Number("1.5")}, runtime["retry"])
}

// A null secret source clears that source and keeps the other one.
func TestPutNullRemovesTheKey(t *testing.T) {
	stored := map[string]any{
		"host": "http://127.0.0.1:1", "password": "inline-private",
		"runtime": map[string]any{"health_check": false, "workers": 4},
	}
	rig, db := webhookRig(t, stored)
	body := `{"version":1,"config":{"username":null,"password_file":null,"runtime":{"workers":null}}}`
	raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook", body, http.StatusOK)
	assert.NotContains(t, string(raw), "null")

	entry, err := db.GetOutputConfig(t.Context(), "webhook")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, map[string]any{
		"host": "http://127.0.0.1:1", "password": "inline-private",
		"runtime": map[string]any{"health_check": false},
	}, entry.Config, "a null password_file does not replace the inline password")

	read := requestSecretContract(t, rig.Server, http.MethodGet, "/api/v1/pipeline/outputs/webhook", "", http.StatusOK)
	assert.False(t, strings.Contains(string(read), ": null") || strings.Contains(string(read), ":null"), "%s", read)
	statuses := rig.Server.pipeline.CollectOutputStatus()
	require.Len(t, statuses, 1)
}

func TestPutEmptySecretFileIsNotSet(t *testing.T) {
	rig, _ := webhookRig(t, nil)
	body := `{"version":0,"config":{"host":"http://127.0.0.1:1","password":"inline-private","password_file":"","runtime":{"health_check":false}}}`
	raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook", body, http.StatusOK)
	assert.NotContains(t, string(raw), "unknown keys")
}

func TestPutRefusesUnknownKeysEvenWhenNull(t *testing.T) {
	stored := map[string]any{"host": "http://127.0.0.1:1", "runtime": map[string]any{"health_check": false}}
	for _, tt := range []struct {
		patch string
		want  string // empty: accepted
	}{
		{patch: `{"typo":null}`, want: "unknown keys: typo"},
		{patch: `{"runtime":{"wrokers":null}}`, want: "unknown keys: runtime.wrokers"},
		{patch: `{"typo":null,"other":null}`, want: "unknown keys: other, typo"},
		{patch: `{"username":null}`},
		{patch: `{"USERNAME":null}`},
		{patch: `{"password_file":null}`},
		{patch: `{"runtime":{"retry":null}}`},
		{patch: `{"runtime":{"retry":{"max_attempts":null}}}`},
		{patch: `{"headers":{"X-New":null}}`},
		{patch: `{"headers":{"X-New":{"secrets":null}}}`},
	} {
		t.Run(tt.patch, func(t *testing.T) {
			rig, db := webhookRig(t, stored)
			status := http.StatusOK
			if tt.want != "" {
				status = http.StatusBadRequest
			}
			raw := requestSecretContract(t, rig.Server, http.MethodPut, "/api/v1/pipeline/outputs/webhook",
				`{"version":1,"config":`+tt.patch+`}`, status)
			entry, err := db.GetOutputConfig(t.Context(), "webhook")
			require.NoError(t, err)
			if tt.want != "" {
				assert.Contains(t, string(raw), tt.want)
				assert.Equal(t, int64(1), entry.Version, "nothing is stored")
				return
			}
			assert.NotContains(t, string(raw), "null")
		})
	}
}
