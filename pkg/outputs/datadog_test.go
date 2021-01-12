package outputs

import (
	"encoding/json"
	"testing"

	"github.com/falcosecurity/falcosidekick/pkg/types"

	"github.com/stretchr/testify/require"
)

func TestNewDatadogPayload(t *testing.T) {
	expectedOutput := `{"title":"Test rule","text":"This is a test from falcosidekick","alert_type":"info","source_type_name":"falco","tags":["proc.name:falcosidekick"]}`

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	s, _ := json.Marshal(newDatadogPayload(f))

	var o1, o2 datadogPayload
	require.Nil(t, json.Unmarshal([]byte(expectedOutput), &o1))
	require.Nil(t, json.Unmarshal(s, &o2))

	require.Equal(t, o1, o2)
}
