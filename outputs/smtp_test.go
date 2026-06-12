// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

// The Date header must be RFC 5322 compliant; otherwise receivers that normalize a
// malformed Date on inbound (e.g. Microsoft 365) rewrite it and break the DKIM
// signature, since Date is a signed header.
func TestNewSMTPPayloadDateHeaderIsRFC5322(t *testing.T) {
	var f types.FalcoPayload
	require.Nil(t, json.Unmarshal([]byte(falcoTestInput), &f))

	config := &types.Configuration{}
	config.SMTP.From = "falco@localhost"
	config.SMTP.To = "alerts@localhost"
	config.SMTP.OutputFormat = Text

	payload := newSMTPPayload(f, config)

	// falcoTestInput time is 2001-01-01T01:10:00Z (a Monday) -> RFC 5322 / time.RFC1123Z form.
	require.Contains(t, payload.Body, "Date: Mon, 01 Jan 2001 01:10:00 +0000\n")
}
