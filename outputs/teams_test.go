// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
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
						Name:  "rule",
						Value: "Test rule",
					},
					{
						Name:  "priority",
						Value: "Debug",
					},
					{
						Name:  "source",
						Value: "syscalls",
					},
					{
						Name:  "hostname",
						Value: "test-host",
					},
					{
						Name:  "proc.name",
						Value: "falcosidekick",
					},
					{
						Name:  "tags",
						Value: "example, test",
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
