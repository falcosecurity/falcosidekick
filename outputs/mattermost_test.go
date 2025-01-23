// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"

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
						Title: "rule",
						Value: "Test rule",
						Short: true,
					},
					{
						Title: "hostname",
						Value: "test-host",
						Short: true,
					},
					{
						Title: "priority",
						Value: "Debug",
						Short: true,
					},
					{
						Title: "source",
						Value: "syscalls",
						Short: true,
					},
					{
						Title: "tags",
						Value: "example, test",
						Short: true,
					},
					{
						Title: "proc.name",
						Value: "falcosidekick",
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
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	config := &types.Configuration{
		Mattermost: types.MattermostOutputConfig{
			Username: "Falcosidekick",
			Icon:     "https://raw.githubusercontent.com/falcosecurity/falcosidekick/master/imgs/falcosidekick.png",
		},
	}

	var err error
	config.Mattermost.MessageFormatTemplate, err = template.New("").Parse("Rule: {{ .Rule }} Priority: {{ .Priority }}")
	require.Nil(t, err)

	output := newMattermostPayload(f, config)
	require.Equal(t, output, expectedOutput)
}
