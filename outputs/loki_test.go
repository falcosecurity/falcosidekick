package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewLokiPayload(t *testing.T) {
	expectedOutput := lokiPayload{
		Streams: []lokiStream{
			{
				Labels: "{procname=\"falcosidekick\",rule=\"Test rule\",priority=\"Debug\"}",
				Entries: []lokiEntry{
					{
						Ts:   "2001-01-01T01:10:00Z",
						Line: "This is a test from falcosidekick",
					},
				},
			},
		},
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	output := newLokiPayload(f, &types.Configuration{})

	require.Equal(t, output, expectedOutput)
}
