// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewTimescaleDBPayload(t *testing.T) {
	expectedTableName := "test_hypertable"
	expectedTime, _ := time.Parse(time.RFC3339, "2001-01-01T01:10:00Z")
	expectedValues := map[string]any{
		"time":             expectedTime,
		"rule":             "Test rule",
		"priority":         "Debug",
		"source":           "syscalls",
		"output":           "This is a test from falcosidekick",
		"tags":             "test,example",
		"hostname":         "test-host",
		"custom_field_1":   "test-custom-value-1",
		"template_field_1": "falcosidekick",
	}

	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))
	f.OutputFields["custom_field_1"] = "test-custom-value-1"
	f.OutputFields["template_field_1"] = "falcosidekick"

	config := &types.Configuration{
		Customfields: map[string]string{
			"custom_field_1": "test-custom-value-1",
		},
		Templatedfields: map[string]string{
			"template_field_1": `{{ or (index . "proc.name") "null" }}`,
		},
		TimescaleDB: types.TimescaleDBConfig{
			HypertableName: "test_hypertable",
		},
	}
	output := newTimescaleDBPayload(f, config)

	re := regexp.MustCompile(`INSERT\s+INTO\s+(test_hypertable)\s+\((.*)\)\s+VALUES\s+\((.*)\)`)
	submatches := re.FindStringSubmatch(output.SQL)
	tablename := submatches[1]
	cols := strings.Split(submatches[2], ",")

	require.Equal(t, expectedTableName, tablename)
	require.Equal(t, 9, len(cols))
	for i, v := range cols {
		if val, exist := expectedValues[v]; exist {
			require.Equal(t, val, output.Values[i])
		} else {
			require.Fail(t, "Missing expected column: %s", v)
		}
	}
}
