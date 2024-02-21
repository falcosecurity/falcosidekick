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

func TestNewStackStatePayload(t *testing.T) {
	expectedOutput := stackstatePayload{
		CollectionTimestamp: 978311400,
		InternalHostname:    "test-host",
		Events: events{
			"": []eventPayload{
				{
					Context: eventContext{
						Category:           "Alerts",
						Source:             "Falco",
						ElementIdentifiers: []string{},
					},
					EventType: "Falco Security Event",
					Title:     "Test rule",
					Text:      "This is a test from falcosidekick",
					Tags:      []string{"proc.name:falcosidekick", "source:syscalls", "hostname:test-host", "test", "example"},
					Timestamp: 978311400,
				},
			},
		},
		Metrics:       []metrics{},
		ServiceChecks: []serviceChecks{},
		Health:        []health{},
		Topologies:    []topology{},
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	config := &types.Configuration{
		StackState: types.StackStateOutputConfig{
			APIToken:    "test",
			APIUrl:      "https://test.app.stackstate.io",
			ClusterName: "test-cluster",
		},
	}

	output := newStackStatePayload(f, config.StackState)
	require.Equal(t, expectedOutput, output)
}
