// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/PagerDuty/go-pagerduty"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestPagerdutyPayload(t *testing.T) {
	var falcoTestInput = `{"output":"This is a test from falcosidekick","priority":"Debug","rule":"Test rule","hostname":"test-host","time":"2001-01-01T01:10:00Z","output_fields": {"hostname": "test-host", "proc.name":"falcosidekick", "proc.tty": 1234}}`
	var excpectedOutput = pagerduty.V2Event{
		RoutingKey: "",
		Action:     "trigger",
		Payload: &pagerduty.V2Payload{
			Summary:   "This is a test from falcosidekick",
			Source:    "falco",
			Severity:  "critical",
			Timestamp: "2001-01-01T01:10:00Z",
			Component: "",
			Group:     "",
			Class:     "",
			Details: map[string]interface{}{
				"hostname":  "test-host",
				"proc.name": "falcosidekick",
				"proc.tty":  float64(1234),
			},
		},
	}

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)

	event := createPagerdutyEvent(f, types.PagerdutyConfig{})

	require.Equal(t, excpectedOutput, event)
}
