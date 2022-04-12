package outputs

import (
	"encoding/json"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/stretchr/testify/require"
)

func TestNewAlertaPayload(t *testing.T) {
	expectedOut := alertaPayload{
		Resource:    "falco",
		Environment: "falco-test",
		Event:       "Test rule",
		Text:        "This is a test from falcosidekick",
		Severity:    "warning",
		CreateTime:  "2001-01-01T01:10:00.000Z",
		RawData:     `{"output":"This is a test from falcosidekick","priority":"Debug","rule":"Test rule","time":"2001-01-01T01:10:00Z","output_fields":{"proc.name":"falcosidekick","proc.tty":1234}}`,
	}
	attrs := map[string]string{
		"proc.name": "falcosidekick",
		"proc.tty":  "1234",
	}
	expectedOut.Attributes = attrs

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	config := &types.Configuration{
		Alerta: types.AlertaConfig{
			Environment: "falco-test",
		},
	}

	output := newAlertaPayload(f, config)
	require.Equal(t, expectedOut, output)
}
