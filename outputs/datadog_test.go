// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewDatadogPayload(t *testing.T) {
	expectedOutput := `{"title":"Test rule","text":"This is a test from falcosidekick","alert_type":"info","source_type_name":"falco","tags":["proc.name:falcosidekick", "source:syscalls", "hostname:test-host", "example", "test"]}`
	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	s, _ := json.Marshal(newDatadogPayload(f))

	var o1, o2 datadogPayload
	require.Nil(t, json.Unmarshal([]byte(expectedOutput), &o1))
	require.Nil(t, json.Unmarshal(s, &o2))

	require.Equal(t, o1, o2)
}
