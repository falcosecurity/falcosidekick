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
