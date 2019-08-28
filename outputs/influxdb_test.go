package outputs

import (
	"encoding/json"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewInfluxdbPayload(t *testing.T) {
	expectedOutput := `"events,rule=Test_rule,priority=Debug,proc.name=falcosidekick,user.name=falcosidekick value=\"This is a test from falcosidekick\""`

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	influxdbPayload, _ := json.Marshal(newInfluxdbPayload(f, &types.Configuration{}))

	if string(influxdbPayload) != expectedOutput {
		// t.Fatalf("\nexpected payload: \n%v\ngot: \n%v\n", o1, o2)
		t.Fatalf("\nexpected payload: \n%v\ngot: \n%v\n", expectedOutput, string(influxdbPayload))
	}
}
