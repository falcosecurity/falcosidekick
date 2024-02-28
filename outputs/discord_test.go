// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package outputs

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewDiscordPayload(t *testing.T) {
	expectedOutput := discordPayload{
		Content:   "",
		AvatarURL: DefaultIconURL,
		Embeds: []discordEmbedPayload{
			{
				Title:       "",
				Description: "This is a test from falcosidekick",
				Color:       "12370112", // light grey
				Fields: []discordEmbedFieldPayload{
					{
						Name:   "rule",
						Value:  "Test rule",
						Inline: true,
					},
					{
						Name:   "priority",
						Value:  "Debug",
						Inline: true,
					},
					{
						Name:   "source",
						Value:  "syscalls",
						Inline: true,
					},
					{
						Name:   "hostname",
						Value:  "test-host",
						Inline: true,
					},
					{
						Name:   "proc.name",
						Value:  fmt.Sprintf("```%s```", "falcosidekick"),
						Inline: true,
					},
					{
						Name:   "tags",
						Value:  "example, test",
						Inline: true,
					},
					{
						Name:   "time",
						Value:  "2001-01-01 01:10:00 +0000 UTC",
						Inline: true,
					},
				},
			},
		},
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	config := &types.Configuration{
		Discord: types.DiscordOutputConfig{},
	}

	output := newDiscordPayload(f, config)
	require.Equal(t, output, expectedOutput)
}
