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

func TestNewTelegramPayload(t *testing.T) {
	expectedOutput := telegramPayload{
		Text:                  "*\\[Falco\\] \\[Debug\\] Test rule*\n\n• *Time*: 2001\\-01\\-01 01:10:00 \\+0000 UTC\n• *Source*: syscalls\n• *Hostname*: test\\-host\n• *Tags*: test example \n• *Fields*:\n\t  • *proc\\.name*: falcosidekick\n\t  • *proc\\.tty*: 1234\n\n\n**Output**: This is a test from falcosidekick\n",
		ParseMode:             "MarkdownV2",
		DisableWebPagePreview: true,
		ChatID:                "-987654321",
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	config := &types.Configuration{
		Telegram: types.TelegramConfig{
			ChatID: "-987654321",
		},
	}

	output := newTelegramPayload(f, config)
	require.Equal(t, expectedOutput, output)
}
