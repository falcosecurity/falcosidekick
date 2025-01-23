// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"

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
								keyValue{
									TopLabel: "rule",
									Content:  "Test rule",
								},
							},
							{
								keyValue{
									TopLabel: "priority",
									Content:  "Debug",
								},
							},
							{
								keyValue{
									TopLabel: "source",
									Content:  "syscalls",
								},
							},
							{
								keyValue{
									TopLabel: "hostname",
									Content:  "test-host",
								},
							},
							{
								keyValue{
									TopLabel: "proc.name",
									Content:  "falcosidekick",
								},
							},
							{
								keyValue{
									TopLabel: "tags",
									Content:  "example, test",
								},
							},
							{
								keyValue{
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
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	config := &types.Configuration{
		Googlechat: types.GooglechatConfig{},
	}

	var err error
	config.Googlechat.MessageFormatTemplate, err = template.New("").Parse("Rule: {{ .Rule }} Priority: {{ .Priority }}")
	require.Nil(t, err)
	output := newGooglechatPayload(f, config)

	require.Equal(t, output, expectedOutput)
}
