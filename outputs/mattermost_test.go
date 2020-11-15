package outputs

import (
	"encoding/json"
	"reflect"
	"testing"
	"text/template"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestMattermostPayload(t *testing.T) {
	expectedOutput := slackPayload{
		Text:     "Rule: Test rule Priority: Debug",
		Username: "Falcosidekick",
		IconURL:  "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png",
		Attachments: []slackAttachment{
			{
				Fallback: "This is a test from falcosidekick",
				Color:    "#ccfff2",
				Text:     "This is a test from falcosidekick",
				Footer:   "https://github.com/falcosecurity/falcosidekick",
				Fields: []slackAttachmentField{
					{
						Title: "proc.name",
						Value: "falcosidekick",
						Short: true,
					},
					{
						Title: "rule",
						Value: "Test rule",
						Short: true,
					},
					{
						Title: "priority",
						Value: "Debug",
						Short: true,
					},
					{
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
	config := &types.Configuration{
		Mattermost: types.MattermostOutputConfig{
			Username: "Falcosidekick",
			Icon:     "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png",
		},
	}

	config.Mattermost.MessageFormatTemplate, _ = template.New("").Parse("Rule: {{ .Rule }} Priority: {{ .Priority }}")
	output := newMattermostPayload(f, config)
	if !reflect.DeepEqual(output, expectedOutput) {
		t.Fatalf("\nexpected payload: \n%#v\ngot: \n%#v\n", expectedOutput, output)
	}
}
