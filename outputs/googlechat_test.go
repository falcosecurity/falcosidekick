package outputs

import (
	"encoding/json"
	"reflect"
	"testing"
	"text/template"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewGoogleChatPayload(t *testing.T) {
	expectedOutput := googlechatPayload{
		Text: "Rule: Test rule Priority: Debug",
		Cards: []card{
			{
				Sections: []section{
					{
						Widgets: []widget{
							{
								keyValue: keyValue{
									TopLabel: "proc.name",
									Content:  "falcosidekick",
								},
							},
							{
								keyValue: keyValue{
									TopLabel: "rule",
									Content:  "Test rule",
								},
							},
							{
								keyValue: keyValue{
									TopLabel: "priority",
									Content:  "Debug",
								},
							},
							{
								keyValue: keyValue{
									TopLabel: "time",
									Content:  "2001-01-01 01:10:00 +0000 UTC",
								},
							},
						},
					},
				},
			},
		},
	}

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	config := &types.Configuration{
		Googlechat: types.GooglechatConfig{},
	}

	config.Googlechat.MessageFormatTemplate, _ = template.New("").Parse("Rule: {{ .Rule }} Priority: {{ .Priority }}")
	output := newGooglechatPayload(f, config)

	if !reflect.DeepEqual(output, expectedOutput) {
		t.Fatalf("\nexpected payload: \n%#v\ngot: \n%#v\n", expectedOutput, output)
	}
}
