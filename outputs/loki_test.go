package outputs

import (
	"encoding/json"
	"reflect"
	"testing"

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
	json.Unmarshal([]byte(falcoTestInput), &f)
	output := newLokiPayload(f, &types.Configuration{})

	if !reflect.DeepEqual(output, expectedOutput) {
		t.Fatalf("\nexpected payload: \n%#v\ngot: \n%#v\n", expectedOutput, output)
	}
}
