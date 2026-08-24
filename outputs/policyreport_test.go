// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewResultTimestamp(t *testing.T) {
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	result := newResult(f)

	// falcoTestInput carries 2001-01-01T01:10:00Z, which is 978311400 seconds
	// since the Unix epoch.
	require.Equal(t, int64(978311400), result.Timestamp.Seconds)
	require.Equal(t, int32(0), result.Timestamp.Nanos)

	// The event time has to survive the round trip into the PolicyReport
	// result: consumers use this field to order events and to decide whether
	// a result is too old to accept.
	require.Equal(t, f.Time.UTC(), time.Unix(result.Timestamp.Seconds, int64(result.Timestamp.Nanos)).UTC())
}
