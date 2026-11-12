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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type jsonInner struct {
	Maybe *time.Duration `json:"maybe,omitempty"`
	Wait  time.Duration  `json:"wait"`
}

type jsonEmbedded struct {
	Timeout time.Duration `json:"timeout"`
}

type jsonOuter struct {
	*jsonEmbedded
	Ptr      *jsonInner     `json:"ptr,omitempty"`
	Nil      *jsonInner     `json:"nil"`
	Map      map[string]int `json:"map"`
	Inner    jsonInner      `json:"inner"`
	Skipped  string         `json:"-"`
	Empty    string         `json:"empty,omitempty"`
	Raw      json.Number    `json:"raw"`
	Labels   []string       `json:"labels"`
	Untagged int            //nolint:tagliatelle // the encoding/json default name is under test
	hidden   int            //nolint:unused // unexported fields are skipped
}

func TestDurationsAsStrings(t *testing.T) {
	maybe := 1500 * time.Millisecond
	v := jsonOuter{
		jsonEmbedded: &jsonEmbedded{Timeout: time.Hour},
		Inner:        jsonInner{Wait: 30 * time.Second},
		Ptr:          &jsonInner{Wait: 0, Maybe: &maybe},
		Skipped:      "no",
		Labels:       []string{"a"},
		Raw:          "12",
		Untagged:     3,
		Map:          map[string]int{"k": 1},
	}
	data, err := json.Marshal(durationsAsStrings(v))
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"timeout": "1h",
		"inner": {"wait": "30s"},
		"ptr": {"wait": "0s", "maybe": "1.5s"},
		"nil": null,
		"labels": ["a"],
		"raw": 12,
		"Untagged": 3,
		"map": {"k": 1}
	}`, string(data))

	plain, err := json.Marshal(v)
	require.NoError(t, err)
	var shape, converted map[string]any
	require.NoError(t, json.Unmarshal(plain, &shape))
	require.NoError(t, json.Unmarshal(data, &converted))
	assert.ElementsMatch(t, keys(shape), keys(converted), "the same keys as encoding/json writes")
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
