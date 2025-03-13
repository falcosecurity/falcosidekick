// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewAzureSentinelPayload(t *testing.T) {
	expected := map[string]interface{}{
		"Rule":     "Test rule",
		"Priority": "Debug",
		"Source":   "syscalls",
		"Output":   "This is a test from falcosidekick",
		"Time":     "2001-01-01T01:10:00Z",
		"Hostname": "test-host",
		"proc.name": "falcosidekick",
		// JSON unmarshaling converts numbers to float64
		"proc.tty": float64(1234),
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	payload := newAzureSentinelPayload(f)
	require.Equal(t, 1, len(payload))
	
	// Compare expected map keys and values
	for key, expectedVal := range expected {
		val, exists := payload[0][key]
		require.True(t, exists, "Expected key %s does not exist in payload", key)
		require.Equal(t, expectedVal, val, "Value mismatch for key %s", key)
	}
}
