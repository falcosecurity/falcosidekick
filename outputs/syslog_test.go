// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"expvar"
	"io"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	otlpmetrics "github.com/falcosecurity/falcosidekick/outputs/otlp_metrics"
	"github.com/falcosecurity/falcosidekick/types"
)

func TestSyslogPostClosesConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	config := &types.Configuration{}
	config.Syslog.Host = host
	config.Syslog.Port = port
	config.Syslog.Protocol = TCP

	stats := &types.Statistics{Syslog: expvar.NewMap("syslog_test")}
	client := &Client{
		OutputType:  "Syslog",
		Config:      config,
		Stats:       stats,
		PromStats:   &types.PromStatistics{Outputs: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "syslog_test_prom", Help: "test"}, []string{"destination", "status"})},
		OTLPMetrics: &otlpmetrics.OTLPMetrics{Outputs: noopCounter{}},
	}

	client.SyslogPost(types.FalcoPayload{Rule: "Test rule", Priority: types.Warning, Output: "test output"})

	conn, err := ln.Accept()
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	data, err := io.ReadAll(conn)
	require.NoError(t, err, "SyslogPost left the connection open")
	require.Contains(t, string(data), "Test rule")
	require.Equal(t, int64(1), getExpvarInt64(t, stats.Syslog, OK))
}
