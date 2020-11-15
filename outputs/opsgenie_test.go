package outputs

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewOpsgeniePayload(t *testing.T) {
	expectedOutput := opsgeniePayload{
		Message:     "This is a test from falcosidekick",
		Entity:      "Falcosidekick",
		Description: "Test rule",
		Details: map[string]string{
			"proc.name": "falcosidekick",
		},
		Priority: "P5",
	}

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	output := newOpsgeniePayload(f, &types.Configuration{})

	if !reflect.DeepEqual(output, expectedOutput) {
		t.Fatalf("\nexpected payload: \n%#v\ngot: \n%#v\n", expectedOutput, output)
	}
}
