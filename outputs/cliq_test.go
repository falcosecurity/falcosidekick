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

func TestNewCliqPayload(t *testing.T) {
	expectedOutput := cliqPayload{
		Text: "\U000026AA Rule: Test rule Priority: Debug",
		Bot: cliqBot{
			Name:  "Falco Sidekick",
			Image: DefaultIconURL,
		},
		Slides: []cliqSlide{
			{
				Type: "text",
				Data: "This is a test from falcosidekick",
			},
			{
				Type:  "table",
				Title: "",
				Data: &cliqTableData{
					Headers: []string{
						"field",
						"value",
					},
					Rows: []cliqTableRow{
						{
							Field: "rule",
							Value: "Test rule",
						},
						{
							Field: "priority",
							Value: "Debug",
						},
						{
							Field: "hostname",
							Value: "test-host",
						},
						{
							Field: "proc.name",
							Value: "falcosidekick",
						},
						{
							Field: "time",
							Value: "2001-01-01 01:10:00 +0000 UTC",
						},
					},
				},
			},
		},
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	config := &types.Configuration{
		Cliq: types.CliqOutputConfig{
			Icon:     DefaultIconURL,
			UseEmoji: true,
		},
	}

	var err error
	config.Cliq.MessageFormatTemplate, err = template.New("").Parse("Rule: {{ .Rule }} Priority: {{ .Priority }}")
	require.Nil(t, err)

	output := newCliqPayload(f, config)
	require.Equal(t, output, expectedOutput)
}
