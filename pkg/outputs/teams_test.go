package outputs

import (
	"encoding/json"
	"testing"

	"github.com/falcosecurity/falcosidekick/pkg/types"

	"github.com/stretchr/testify/require"
)

func TestNewTeamsPayload(t *testing.T) {
	expectedOutput := teamsPayload{
		Type:       "MessageCard",
		Summary:    "This is a test from falcosidekick",
		ThemeColor: "ccfff2",
		Sections: []teamsSection{
			{
				ActivityTitle:    "Falco Sidekick",
				ActivitySubTitle: "2001-01-01 01:10:00 +0000 UTC",
				ActivityImage:    "",
				Text:             "This is a test from falcosidekick",
				Facts: []teamsFact{
					{
						Name:  "proc.name",
						Value: "falcosidekick",
					},
					{
						Name:  "rule",
						Value: "Test rule",
					},
					{
						Name:  "priority",
						Value: "Debug",
					},
				},
			},
		},
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	output := newTeamsPayload(f, &types.Configuration{})
	require.Equal(t, output, expectedOutput)
}
