package outputs

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Issif/falcosidekick/types"
)

func TestNewAlertmanagerPayload(t *testing.T) {
	expectedOutput := `[{"labels":{"proc_name":"falcosidekick","rule":"Test rule","source":"falco","user_name":"falcosidekick"},"annotations":{"info":"This is a test from falcosidekick","summary":"Test rule"}}]`

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	s, _ := json.Marshal(newAlertmanagerPayload(f))

	var o1, o2 alertmanagerPayload
	json.Unmarshal([]byte(expectedOutput), &o1)
	json.Unmarshal([]byte(s), &o2)

	if !reflect.DeepEqual(o1, o2) {
		// t.Fatalf("\nexpected payload: \n%v\ngot: \n%v\n", o1, o2)
		t.Fatalf("\nexpected payload: \n%v\ngot: \n%v\n", expectedOutput, string(s))
	}
}
