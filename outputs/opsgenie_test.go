// SPDX-License-Identifier: MIT OR Apache-2.0

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
