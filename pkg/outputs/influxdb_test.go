package outputs

import (
	"encoding/json"
	"testing"

	"github.com/falcosecurity/falcosidekick/pkg/types"

	"github.com/stretchr/testify/require"
)

func TestNewInfluxdbPayload(t *testing.T) {
	expectedOutput := `"events,rule=Test_rule,priority=Debug,proc.name=falcosidekick value=\"This is a test from falcosidekick\""`

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	influxdbPayload, err := json.Marshal(newInfluxdbPayload(f, &types.Configuration{}))
	require.Nil(t, err)

	require.Equal(t, string(influxdbPayload), expectedOutput)
}
