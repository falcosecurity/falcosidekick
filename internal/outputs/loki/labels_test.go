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

package loki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSerializeLabelsIsDeterministic(t *testing.T) {
	labels := map[string]string{"z": "1", "a": "2", "m": "3"}
	s1 := serializeLabels(labels)
	s2 := serializeLabels(labels)
	assert.Equal(t, s1, s2)
	assert.Equal(t, `{a="2",m="3",z="1"}`, s1)
}

func TestSerializeLabelsFormat(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{name: "empty", labels: map[string]string{}, want: `{}`},
		{name: "single", labels: map[string]string{"rule": "r"}, want: `{rule="r"}`},
		{name: "empty value", labels: map[string]string{"rule": ""}, want: `{rule=""}`},
		{name: "value quoted", labels: map[string]string{"rule": `a"b,c`}, want: `{rule="a\"b,c"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, serializeLabels(tc.labels))
		})
	}
}

// The key groups events into streams: two label sets must never share it.
func TestSerializeLabelsNeverCollides(t *testing.T) {
	one := map[string]string{"a": `x",b="y`}
	two := map[string]string{"a": "x", "b": "y"}
	assert.NotEqual(t, serializeLabels(one), serializeLabels(two))
}
