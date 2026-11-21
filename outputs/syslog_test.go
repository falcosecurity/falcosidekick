// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"crypto/tls"
	"expvar"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

func newTLSSyslogTestClient(t *testing.T, name string, host, port string, checkCert bool) (*Client, *types.Statistics) {
	t.Helper()
	config := &types.Configuration{}
	config.Syslog.Host = host
	config.Syslog.Port = port
	config.Syslog.Protocol = TCP
	config.Syslog.TLS = true
	config.Syslog.CheckCert = checkCert

	stats := &types.Statistics{Syslog: expvar.NewMap(name)}
	return &Client{
		OutputType:  "Syslog",
		Config:      config,
		Stats:       stats,
		PromStats:   &types.PromStatistics{Outputs: prometheus.NewCounterVec(prometheus.CounterOpts{Name: name + "_prom", Help: "test"}, []string{"destination", "status"})},
		OTLPMetrics: &otlpmetrics.OTLPMetrics{Outputs: noopCounter{}},
	}, stats
}

func newTLSSyslogTestListener(t *testing.T) (net.Listener, string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: srv.TLS.Certificates, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	host, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return ln, host, port
}

func TestSyslogPostTLS(t *testing.T) {
	ln, host, port := newTLSSyslogTestListener(t)
	client, stats := newTLSSyslogTestClient(t, "syslog_tls_test", host, port, false)

	done := make(chan struct{})
	go func() {
		defer close(done)
		client.SyslogPost(types.FalcoPayload{Rule: "Test rule", Priority: types.Warning, Output: "test output"})
	}()

	conn, err := ln.Accept()
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	data, err := io.ReadAll(conn)
	require.NoError(t, err)
	<-done

	frame := string(data)
	length, msg, found := strings.Cut(frame, " ")
	require.True(t, found, "missing octet-counting prefix: %q", frame)
	require.Equal(t, strconv.Itoa(len(msg)), length)
	require.True(t, strings.HasPrefix(msg, "<4>1 "), "unexpected header: %q", msg)
	require.Contains(t, msg, " Falco - - - ")
	require.Contains(t, msg, "Test rule")
	require.Equal(t, int64(1), getExpvarInt64(t, stats.Syslog, OK))
}

func TestSyslogPostTLSCheckCert(t *testing.T) {
	ln, host, port := newTLSSyslogTestListener(t)
	client, stats := newTLSSyslogTestClient(t, "syslog_tls_checkcert_test", host, port, true)

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			// the handshake fails because the certificate is not trusted
			_, _ = io.Copy(io.Discard, conn)
			conn.Close()
		}
	}()

	client.SyslogPost(types.FalcoPayload{Rule: "Test rule", Priority: types.Warning, Output: "test output"})

	require.Equal(t, int64(1), getExpvarInt64(t, stats.Syslog, Error))
	require.Equal(t, int64(0), getExpvarInt64(t, stats.Syslog, OK))
}

func TestNewSyslogClientTLSRequiresTCP(t *testing.T) {
	config := &types.Configuration{}
	config.Syslog.Protocol = UDP
	config.Syslog.TLS = true

	_, err := NewSyslogClient(config, nil, nil, nil, nil, nil)
	require.Error(t, err)

	config.Syslog.Protocol = TCP
	_, err = NewSyslogClient(config, nil, nil, nil, nil, nil)
	require.NoError(t, err)
}

func TestFormatSyslogTLSFrame(t *testing.T) {
	ts := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	got := formatSyslogTLSFrame(3, ts, "", []byte(`{"a":1}`))
	require.Equal(t, `47 <3>1 2026-10-22T12:00:00Z - Falco - - - {"a":1}`, got)
}
