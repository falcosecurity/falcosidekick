package outputs

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewSlackPayload(t *testing.T) {
	expectedOutput := slackPayload{
		Username: "Falcosidekick",
		IconURL:  "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png",
		Attachments: []slackAttachment{
			slackAttachment{
				Fallback: "This is a test from falcosidekick",
				Color:    "#ccfff2",
				Text:     "This is a test from falcosidekick",
				Footer:   "https://github.com/falcosecurity/falcosidekick",
				Fields: []slackAttachmentField{
					slackAttachmentField{
						Title: "proc.name",
						Value: "falcosidekick",
						Short: true,
					},
					slackAttachmentField{
						Title: "rule",
						Value: "Test rule",
						Short: true,
					},
					slackAttachmentField{
						Title: "priority",
						Value: "Debug",
						Short: true,
					},
					slackAttachmentField{
						Title: "time",
						Value: "2001-01-01 01:10:00 +0000 UTC",
						Short: false,
					},
				},
			},
		},
	}

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	output := newSlackPayload(f, &types.Configuration{})
	if !reflect.DeepEqual(output, expectedOutput) {
		t.Fatalf("\nexpected payload: \n%#v\ngot: \n%#v\n", expectedOutput, output)
	}
}
