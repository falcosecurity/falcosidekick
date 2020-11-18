package outputs

import (
	"encoding/json"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"

	"github.com/stretchr/testify/require"
)

func TestNewAlertmanagerPayload(t *testing.T) {
	expectedOutput := `[{"labels":{"proc_name":"falcosidekick","rule":"Test rule","source":"falco"},"annotations":{"info":"This is a test from falcosidekick","summary":"Test rule"}}]`

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	s, err := json.Marshal(newAlertmanagerPayload(f))
	require.Nil(t, err)

	var o1, o2 []alertmanagerPayload
	require.Nil(t, json.Unmarshal([]byte(expectedOutput), &o1))
	require.Nil(t, json.Unmarshal(s, &o2))

	require.Equal(t, o1, o2)
}
