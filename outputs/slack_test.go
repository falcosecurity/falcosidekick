package outputs

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Issif/falcosidekick/types"
)

func TestNewSlackPayload(t *testing.T) {
	expectedOutput := `{"username":"Falco Sidekick","icon_url":"https://raw.githubusercontent.com/Issif/falcosidekick/master/imgs/falcosidekick.png","attachments":[{"fallback":"This is a test from falcosidekick","color":"#ccfff2","text":"This is a test from falcosidekick","fields":[{"title":"proc.name","value":"falcosidekick","short":true},{"title":"user.name","value":"falcosidekick","short":true},{"title":"rule","value":"Test rule","short":true},{"title":"priority","value":"Debug","short":true},{"title":"time","value":"2001-01-01 01:10:00 +0000 UTC","short":false}],"footer":"https://github.com/Issif/falcosidekick"}]}`

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	s, _ := json.Marshal(newSlackPayload(f, &types.Configuration{}))

	var o1, o2 slackPayload
	json.Unmarshal([]byte(expectedOutput), &o1)
	json.Unmarshal([]byte(s), &o2)

	if !reflect.DeepEqual(o1, o2) {
		// t.Fatalf("\nexpected payload: \n%v\ngot: \n%v\n", o1, o2)
		t.Fatalf("\nexpected payload: \n%v\ngot: \n%v\n", expectedOutput, string(s))
	}
}
