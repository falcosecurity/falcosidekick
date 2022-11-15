package outputs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewAlertmanagerPayloadO(t *testing.T) {
	expectedOutput := `[{"labels":{"proc_name":"falcosidekick","priority":"Debug","proc_tty":"1234","eventsource":"syscalls","hostname":"test-host","rule":"Test rule","source":"falco","tags":"test,example"},"annotations":{"info":"This is a test from falcosidekick","summary":"Test rule"}}]`
	var f types.FalcoPayload
	d := json.NewDecoder(strings.NewReader(falcoTestInput))
	d.UseNumber()
	err := d.Decode(&f) //have to decode it the way newFalcoPayload does
	require.Nil(t, err)

	config := &types.Configuration{
		Alertmanager: types.AlertmanagerOutputConfig{},
	}

	s, err := json.Marshal(newAlertmanagerPayload(f, config))
	require.Nil(t, err)

	var o1, o2 []alertmanagerPayload
	require.Nil(t, json.Unmarshal([]byte(expectedOutput), &o1))
	require.Nil(t, json.Unmarshal(s, &o2))

	require.Equal(t, o1, o2)
}
