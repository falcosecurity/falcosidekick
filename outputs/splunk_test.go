// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewSplunkPayload(t *testing.T) {
	var falcoEvent types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &falcoEvent))

	expectedOutput := splunkPayload{
		Event:      falcoEvent,
		SourceType: "falcosidekick",
	}

	output := newSplunkPayload(falcoEvent)
	require.Equal(t, expectedOutput, output)
}
