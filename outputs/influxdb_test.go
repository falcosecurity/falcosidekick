// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewInfluxdbPayload(t *testing.T) {
	expectedOutput := `"events,rule=Test_rule,priority=Debug,source=syscalls,proc.name=falcosidekick,hostname=test-host,tags=test_example value=\"This is a test from falcosidekick\""`
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	influxdbPayload, err := json.Marshal(newInfluxdbPayload(f, &types.Configuration{}))
	require.Nil(t, err)

	require.Equal(t, string(influxdbPayload), expectedOutput)
}
