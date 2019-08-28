package outputs

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewTeamsPayload(t *testing.T) {
	expectedOutput := teamsPayload{
		Type:       "MessageCard",
		Summary:    "This is a test from falcosidekick",
		ThemeColor: "ccfff2",
		Sections: []teamsSection{
			teamsSection{
				ActivityTitle:    "Falco Sidekick",
				ActivitySubTitle: "2001-01-01 01:10:00 +0000 UTC",
				ActivityImage:    "",
				Text:             "This is a test from falcosidekick",
				Facts: []teamsFact{
					teamsFact{
						Name:  "proc.name",
						Value: "falcosidekick",
					},
					teamsFact{
						Name:  "user.name",
						Value: "falcosidekick",
					},
					teamsFact{
						Name:  "rule",
						Value: "Test rule",
					},
					teamsFact{
						Name:  "priority",
						Value: "Debug",
					},
				},
			},
		},
	}

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	output := newTeamsPayload(f, &types.Configuration{})
	if !reflect.DeepEqual(output, expectedOutput) {
		t.Fatalf("\nexpected payload: \n%#v\ngot: \n%#v\n", expectedOutput, output)
	}
}
