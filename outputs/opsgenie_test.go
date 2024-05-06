// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewOpsgeniePayload(t *testing.T) {
	expectedOutput := opsgeniePayload{
		Message:     "This is a test from falcosidekick",
		Entity:      "Falcosidekick",
		Description: "Test rule",
		Details: map[string]string{
			"hostname":  "test-host",
			"priority":  "Debug",
			"tags":      "test, example",
			"proc_name": "falcosidekick",
			"rule":      "Test rule",
			"source":    "syscalls",
		},
		Priority: "P5",
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	output := newOpsgeniePayload(f, &types.Configuration{})

	require.Equal(t, output, expectedOutput)
}
