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
			"proc_name": "falcosidekick",
		},
		Priority: "P5",
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	output := newOpsgeniePayload(f, &types.Configuration{})

	require.Equal(t, output, expectedOutput)
}
