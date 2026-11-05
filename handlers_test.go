// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"bytes"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/types"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The SMTP, Kafka, Grafana and GCP Cloud Run clients are only created when
// more settings than the one checked by forwardEvent are set. With a partial
// configuration, forwardEvent must not dispatch to these nil clients.
func TestForwardEventSkipsOutputsWithoutClient(t *testing.T) {
	var buf syncBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	prevConfig := config
	t.Cleanup(func() { config = prevConfig })

	config = &types.Configuration{}
	config.SMTP.HostPort = "localhost:25"
	config.Kafka.HostPort = "localhost:9092"
	config.Grafana.HostPort = "http://localhost:3000"
	config.GCP.CloudRun.Endpoint = "http://localhost:8080"

	forwardEvent(types.FalcoPayload{Rule: "rule", Priority: types.Critical, Time: time.Now()})

	time.Sleep(500 * time.Millisecond)
	require.NotContains(t, buf.String(), "recovered from panic")
}
