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
					{
						Name:  "source",
						Value: "syscalls",
					},
					{
						Name:  "hostname",
						Value: "test-host",
					},
					{
						Name:  "tags",
						Value: "test, example",
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
