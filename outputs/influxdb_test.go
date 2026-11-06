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

	influxdbPayload, err := json.Marshal(newInfluxdbPayload(f))
	require.Nil(t, err)

	require.Equal(t, string(influxdbPayload), expectedOutput)
}

func TestNewInfluxdbPayloadEscapesSpecialCharacters(t *testing.T) {
	input := `{"output":"Shell spawned (cmdline=sh -c \"echo a\\b\")","priority":"Warning","rule":"Terminal shell, in container","time":"2001-01-01T01:10:00Z","source":"syscalls","output_fields":{"proc.cmdline":"java -Da=b,c","k8s.ns.name":""}}`
	expectedOutput := `events,rule=Terminal_shell\,_in_container,priority=Warning,source=syscalls,proc.cmdline=java_-Da\=b\,c value="Shell spawned (cmdline=sh -c \"echo a\\b\")"`
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(input), &f))

	require.Equal(t, expectedOutput, string(newInfluxdbPayload(f)))
}
