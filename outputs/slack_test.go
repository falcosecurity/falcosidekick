package outputs

import (
	"encoding/json"
	"reflect"
	"testing"
	"text/template"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewSlackPayload(t *testing.T) {
	expectedOutput := slackPayload{
		Text:     "Rule: Test rule Priority: Debug",
		Username: "Falcosidekick",
		IconURL:  DefaultIconURL,
		Attachments: []slackAttachment{
			{
				Fallback: "This is a test from falcosidekick",
				Color:    PaleCyan,
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
		Slack: types.SlackOutputConfig{
			Username: "Falcosidekick",
			Icon:     DefaultIconURL,
		},
	}

	config.Slack.MessageFormatTemplate, _ = template.New("").Parse("Rule: {{ .Rule }} Priority: {{ .Priority }}")
	output := newSlackPayload(f, config)

	if !reflect.DeepEqual(output, expectedOutput) {
		t.Fatalf("\nexpected payload: \n%#v\ngot: \n%#v\n", expectedOutput, output)
	}
}
