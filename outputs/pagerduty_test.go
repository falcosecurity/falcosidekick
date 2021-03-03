package outputs

import (
	"encoding/json"
	"github.com/PagerDuty/go-pagerduty"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPagerdutyPayload(t *testing.T) {
	var falcoTestInput = `{"output":"This is a test from falcosidekick","priority":"Debug","rule":"Test rule","time":"2001-01-01T01:10:00Z","output_fields": {"proc.name":"falcosidekick", "proc.tty": 1234}}`

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
