// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package syslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/version"
)

// rfc5424 matches the header of RFC 5424 section 6 as this output writes it.
var rfc5424 = regexp.MustCompile(`^<(\d{1,3})>1 (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z) ([\x21-\x7e]{1,255}) falco - - - (.*)$`)

func newTestDriver(t *testing.T, cfg map[string]any) *driver {
	t.Helper()
	d, err := OutputType.New(cfg, output.Deps{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	return d.(*driver)
}

func TestValidation(t *testing.T) {
	tests := []struct {
		config map[string]any
		name   string
		want   string
	}{
		{name: "minimal", config: map[string]any{"host": "syslog.example"}},
		{name: "ipv6", config: map[string]any{"host": "::1", "protocol": "udp"}},
		{name: "missing host", config: map[string]any{}, want: "host: is required"},
		{name: "host with scheme", config: map[string]any{"host": "tcp://syslog"}, want: "host: must be a host name"},
		{name: "host with path", config: map[string]any{"host": "syslog/x"}, want: "host: must be a host name"},
		{name: "bad protocol", config: map[string]any{"host": "s", "protocol": "relp"}, want: `protocol: must be tcp/udp`},
		{name: "protocol tls is refused", config: map[string]any{"host": "s", "protocol": "tls"}, want: `protocol: must be tcp/udp`},
		{name: "tls over tcp", config: map[string]any{"host": "s", "tls": map[string]any{"enabled": true}}},
		{name: "tls over udp", config: map[string]any{"host": "s", "protocol": "udp", "tls": map[string]any{"enabled": true}}, want: "tls.enabled: requires protocol tcp"},
		{name: "tls_enabled is refused", config: map[string]any{"host": "s", "tls_enabled": true}, want: "tls_enabled"},
		{name: "uppercase protocol", config: map[string]any{"host": "s", "protocol": "TCP"}, want: "protocol"},
		{name: "port too high", config: map[string]any{"host": "s", "port": 70000}, want: "port: must be between 1 and 65535"},
		{name: "negative port", config: map[string]any{"host": "s", "port": -1}, want: "port"},
		{name: "port as string", config: map[string]any{"host": "s", "port": "1514"}},
		{name: "bad format", config: map[string]any{"host": "s", "format": "leef"}, want: `format: must be json/cef`},
		{name: "cef", config: map[string]any{"host": "s", "format": "cef"}},
		{name: "bad facility", config: map[string]any{"host": "s", "facility": "local9"}, want: "facility: must be one of"},
		{name: "tls settings without tls.enabled", config: map[string]any{"host": "s", "tls": map[string]any{"insecure_skip_verify": true}},
			want: "tls.enabled: must be true when other tls settings are set"},
		{name: "missing ca file", config: map[string]any{"host": "s", "tls": map[string]any{"enabled": true, "ca_file": "/does/not/exist"}}, want: "tls.ca_file"},
		{name: "unknown key", config: map[string]any{"host": "s", "minimumpriority": "debug"}, want: "minimumpriority"},
		{name: "v2 checkcert", config: map[string]any{"host": "s", "checkcert": false}, want: "checkcert"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := OutputType.New(tc.config, output.Deps{})
			if tc.want == "" {
				require.NoError(t, err)
				assert.Equal(t, "syslog", d.Name())
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestDefaults(t *testing.T) {
	d := newTestDriver(t, map[string]any{"host": "s"})
	assert.Equal(t, protocolTCP, d.cfg.Protocol)
	assert.Equal(t, 514, d.cfg.Port)
	assert.Equal(t, formatJSON, d.cfg.Format)
	assert.Equal(t, 16, d.facility, "local0")

	d = newTestDriver(t, map[string]any{"host": "s", "tls": map[string]any{"enabled": true}})
	assert.Equal(t, 6514, d.cfg.Port, "RFC 5425 port")
	assert.Equal(t, protocolTCP, d.cfg.Protocol)

	d = newTestDriver(t, map[string]any{"host": "s", "port": 1514, "runtime": map[string]any{"workers": 4}})
	assert.Equal(t, 1514, d.cfg.Port)
	assert.Equal(t, 4, d.RuntimeConfig().Workers)
	require.NoError(t, d.Init(context.Background()))
}

func TestSchema(t *testing.T) {
	fields := map[string]output.SchemaField{}
	for _, f := range OutputType.Schema.Fields {
		fields[f.Name] = f
	}
	assert.True(t, fields["host"].Required)
	assert.Equal(t, []string{"tcp", "udp"}, fields["protocol"].Values)
	assert.Contains(t, fields["facility"].Values, "local0")
	assert.Contains(t, fields, "tls.ca_file")
	assert.Equal(t, false, fields["tls.enabled"].Default)
	assert.Contains(t, fields, "runtime.minimum_priority")
}

func TestPriorityMapping(t *testing.T) {
	tests := []struct {
		priority event.Priority
		facility string
		want     int
	}{
		{event.PriorityEmergency, "local0", 128},
		{event.PriorityAlert, "local0", 129},
		{event.PriorityCritical, "local0", 130},
		{event.PriorityError, "local0", 131},
		{event.PriorityWarning, "local0", 132},
		{event.PriorityNotice, "local0", 133},
		{event.PriorityInformational, "local0", 134},
		{event.PriorityDebug, "local0", 135},
		{event.PriorityWarning, "kern", 4},
		{event.PriorityError, "user", 11},
		{event.PriorityCritical, "local7", 186},
		{event.Priority("bogus"), "kern", 5},
	}
	for _, tc := range tests {
		t.Run(string(tc.priority)+"/"+tc.facility, func(t *testing.T) {
			d := newTestDriver(t, map[string]any{"host": "s", "protocol": "udp", "facility": tc.facility})
			evt := testutil.CreateValidEvent()
			evt.Priority = tc.priority
			msg, err := d.message(evt)
			require.NoError(t, err)
			m := rfc5424.FindStringSubmatch(string(msg))
			require.NotNil(t, m, string(msg))
			assert.Equal(t, strconv.Itoa(tc.want), m[1])
		})
	}
}

func TestJSONMessage(t *testing.T) {
	d := newTestDriver(t, map[string]any{"host": "s", "protocol": "udp"})
	evt := testutil.CreateValidEvent()
	evt.Time = time.Date(2026, 4, 1, 12, 30, 0, 123456789, time.FixedZone("CEST", 2*3600))
	msg, err := d.message(evt)
	require.NoError(t, err)

	m := rfc5424.FindStringSubmatch(string(msg))
	require.NotNil(t, m, string(msg))
	assert.Equal(t, "131", m[1], "local0.err")
	assert.Equal(t, "2026-04-01T10:30:00.123456Z", m[2], "UTC with microseconds")
	assert.Equal(t, "node-1", m[3], "event hostname")

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(m[4]), &got))
	assert.Equal(t, evt.Rule, got["rule"])
	assert.Equal(t, "Error", got["priority"], "the event JSON keeps Falco's casing")
	assert.Equal(t, evt.Output, got["output"])
	assert.Equal(t, "/bin/hack", got["output_fields"].(map[string]any)["fd.name"])
}

func TestHostnameFallback(t *testing.T) {
	d := newTestDriver(t, map[string]any{"host": "s", "protocol": "udp"})
	d.localHostname = "sidekick-1"
	for _, hostname := range []string{"", "has space", strings.Repeat("h", 256), "ünïcode"} {
		evt := testutil.CreateValidEvent()
		evt.Hostname = hostname
		msg, err := d.message(evt)
		require.NoError(t, err)
		m := rfc5424.FindStringSubmatch(string(msg))
		require.NotNil(t, m, string(msg))
		assert.Equal(t, "sidekick-1", m[3], "hostname %q", hostname)
	}
	assert.True(t, validHostname("node-1.example"))
	assert.False(t, validHostname(""))
}

func TestOctetCountingFrame(t *testing.T) {
	for _, tlsEnabled := range []bool{false, true} {
		d := newTestDriver(t, map[string]any{"host": "s", "protocol": "tcp", "tls": map[string]any{"enabled": tlsEnabled}})
		msg, err := d.message(testutil.CreateValidEvent())
		require.NoError(t, err)
		length, rest, ok := strings.Cut(string(msg), " ")
		require.True(t, ok)
		n, err := strconv.Atoi(length)
		require.NoError(t, err)
		assert.Len(t, rest, n, "tls %t", tlsEnabled)
		assert.True(t, rfc5424.MatchString(rest))
	}
}

func TestCEFMessage(t *testing.T) {
	d := newTestDriver(t, map[string]any{"host": "s", "protocol": "udp", "format": "cef"})
	evt := testutil.CreateValidEvent()
	evt.Rule = "Pipe | and \\ in rule\nwith = sign"
	evt.Output = "a=b\r\nnext line"
	evt.OutputFields = map[string]any{"z.field": "last", "a.field": `x=y\z`, "n.count": 3}
	msg, err := d.message(evt)
	require.NoError(t, err)
	m := rfc5424.FindStringSubmatch(string(msg))
	require.NotNil(t, m, string(msg))
	rule := `Pipe \| and \\ in rule with = sign`
	assert.Equal(t,
		`CEF:0|Falcosecurity|Falcosidekick|dev|`+rule+`|`+rule+`|7|rt=1775039400000 dvchost=node-1 msg=a\=b\r\nnext line `+
			`externalId=test-uuid-001 cat=syscall FalcoFalcosidekickTags=filesystem,mitre_persistence `+
			`cs1Label=a.field cs1=x\=y\\z cs2Label=n.count cs2=3 cs3Label=z.field cs3=last`,
		m[4])

	evt.Hostname, evt.Tags, evt.UUID, evt.Source = "", nil, "", ""
	body := cefBody(evt)
	for _, absent := range []string{"dvchost=", "FalcoFalcosidekickTags=", "externalId=", "cat="} {
		assert.NotContains(t, body, absent)
	}

	for p, want := range map[event.Priority]string{
		event.PriorityDebug: "0", event.PriorityInformational: "3", event.PriorityNotice: "4", event.PriorityWarning: "6",
		event.PriorityError: "7", event.PriorityCritical: "8", event.PriorityAlert: "9", event.PriorityEmergency: "10",
	} {
		evt.Priority = p
		assert.Contains(t, cefBody(evt), "|"+want+"|rt=", p)
	}
}

func TestCEFVersionIsSidekicks(t *testing.T) {
	previous := version.Version
	version.Version = "3.0.0|beta"
	t.Cleanup(func() { version.Version = previous })
	assert.True(t, strings.HasPrefix(cefBody(testutil.CreateValidEvent()),
		`CEF:0|Falcosecurity|Falcosidekick|3.0.0\|beta|Write below binary dir|Write below binary dir|`))
}

func TestCEFMessageIsCapped(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Output = strings.Repeat("é", 1023) + "cut"
	body := cefBody(evt)
	assert.Contains(t, body, " msg="+strings.Repeat("é", 1023)+" ", "1023 characters, not bytes")
	assert.NotContains(t, body, "cut")
}

func TestCEFCustomStringsAreCapped(t *testing.T) {
	evt := testutil.CreateValidEvent()
	label := strings.Repeat("l", 1023)
	evt.OutputFields = map[string]any{label + "cutlabel": strings.Repeat("é", 4000) + "cutvalue"}
	body := cefBody(evt)
	assert.Contains(t, body, " cs1Label="+label+" ", "a label is 1023 characters")
	assert.True(t, strings.HasSuffix(body, " cs1="+strings.Repeat("é", 4000)), "a value is 4000 characters, not bytes")
	assert.NotContains(t, body, "cutlabel")
	assert.NotContains(t, body, "cutvalue")
}

// Output fields beyond cs6 go in vendor keys, never in keys outside the CEF dictionary without the prefix.
func TestCEFOutputFieldsBeyondSix(t *testing.T) {
	evt := testutil.CreateValidEvent()
	evt.Tags = nil
	evt.OutputFields = map[string]any{
		"a1": "1", "a2": "2", "a3": "3", "a4": "4", "a5": "5", "a6": "6",
		"proc.aname[2]": "bash", "proc.aname.2": "dup", "tags": "field", "k8s.ns.name": nil,
	}
	body := cefBody(evt)
	for i := 1; i <= 6; i++ {
		n := strconv.Itoa(i)
		assert.Contains(t, body, " cs"+n+"Label=a"+n+" cs"+n+"="+n)
	}
	assert.NotContains(t, body, "cs7")
	assert.True(t, strings.HasSuffix(body,
		" FalcoFalcosidekickK8sNsName=<nil> FalcoFalcosidekickProcAname2=dup FalcoFalcosidekickProcAname22=bash FalcoFalcosidekickTags2=field"), body)

	used := map[string]bool{}
	assert.Equal(t, "FalcoFalcosidekickFdName", cefVendorKey("fd.name", used))
	assert.Equal(t, "FalcoFalcosidekickFdName2", cefVendorKey("fd_name", used))
	assert.Equal(t, "FalcoFalcosidekickEvtArgPID", cefVendorKey("evt.arg.PID", used))
}

// streamServer sends each octet-counted frame it reads on the returned channel.
func streamServer(t *testing.T, ln net.Listener) (frames <-chan string, conns <-chan net.Conn) {
	t.Helper()
	out := make(chan string, 16)
	accepted := make(chan net.Conn, 16)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
			go func() {
				defer func() { _ = conn.Close() }()
				r := bufio.NewReader(conn)
				for {
					length, err := r.ReadString(' ')
					if err != nil {
						return
					}
					n, err := strconv.Atoi(strings.TrimSuffix(length, " "))
					if err != nil {
						out <- "bad frame: " + length
						return
					}
					buf := make([]byte, n)
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					out <- string(buf)
				}
			}()
		}
	}()
	return out, accepted
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return ln
}

func hostPort(t *testing.T, addr string) map[string]any {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	return map[string]any{"host": host, "port": port}
}

func receive(t *testing.T, frames <-chan string) string {
	t.Helper()
	select {
	case f := <-frames:
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("no frame received")
		return ""
	}
}

func TestTCPDeliveryAndReconnect(t *testing.T) {
	ln := listen(t)
	frames, conns := streamServer(t, ln)
	d := newTestDriver(t, hostPort(t, ln.Addr().String()))
	ctx := context.Background()

	require.NoError(t, d.HealthCheck(ctx))
	require.NoError(t, d.Send(ctx, testutil.CreateValidEvent()))
	require.NoError(t, d.Send(ctx, testutil.CreateValidEvent()))
	assert.True(t, rfc5424.MatchString(receive(t, frames)))
	assert.True(t, rfc5424.MatchString(receive(t, frames)))

	first := <-conns
	assert.Empty(t, conns, "one connection serves every send")
	require.NoError(t, first.Close())
	time.Sleep(50 * time.Millisecond)

	require.NoError(t, d.Send(ctx, testutil.CreateValidEvent()), "a connection closed by the receiver is replaced")
	assert.True(t, rfc5424.MatchString(receive(t, frames)))
	select {
	case <-conns:
	case <-time.After(time.Second):
		t.Fatal("no new connection")
	}

	require.NoError(t, d.Close())
	err := d.Send(ctx, testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "syslog dial")
	require.NoError(t, d.Close(), "close is idempotent")
}

func TestCloseClosesConnection(t *testing.T) {
	ln := listen(t)
	t.Cleanup(func() { _ = ln.Close() })
	d := newTestDriver(t, hostPort(t, ln.Addr().String()))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	conn, err := ln.Accept()
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, d.Close())
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	data, err := io.ReadAll(conn)
	require.NoError(t, err, "the receiver sees EOF once Close returns")
	assert.NotEmpty(t, data)
}

func TestUDPDelivery(t *testing.T) {
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	cfg := hostPort(t, pc.LocalAddr().String())
	cfg["protocol"] = "udp"
	cfg["format"] = "cef"
	d := newTestDriver(t, cfg)

	require.NoError(t, d.HealthCheck(context.Background()), "udp has no probe")
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	buf := make([]byte, 65535)
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	m := rfc5424.FindStringSubmatch(string(buf[:n]))
	require.NotNil(t, m, "one datagram is one message without framing")
	assert.True(t, strings.HasPrefix(m[4], "CEF:0|"))
}

// tlsServer returns a TLS listener valid for 127.0.0.1 and a CA file that trusts it.
func tlsServer(t *testing.T) (ln net.Listener, caFile string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	cert := srv.Certificate()
	tlsCfg := srv.TLS.Clone()
	srv.Close()
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600))
	tlsCfg.NextProtos = nil
	return tls.NewListener(listen(t), tlsCfg), caFile
}

func TestTLSDelivery(t *testing.T) {
	ln, caFile := tlsServer(t)
	frames, _ := streamServer(t, ln)
	cfg := hostPort(t, ln.Addr().String())
	cfg["tls"] = map[string]any{"enabled": true, "ca_file": caFile}
	d := newTestDriver(t, cfg)

	require.NoError(t, d.HealthCheck(context.Background()))
	require.NoError(t, d.Send(context.Background(), testutil.CreateValidEvent()))
	assert.True(t, rfc5424.MatchString(receive(t, frames)))
}

func TestTLSUntrustedIsMisconfigured(t *testing.T) {
	ln, _ := tlsServer(t)
	streamServer(t, ln)
	cfg := hostPort(t, ln.Addr().String())
	cfg["tls"] = map[string]any{"enabled": true}
	d := newTestDriver(t, cfg)

	err := d.HealthCheck(context.Background())
	require.ErrorIs(t, err, output.ErrMisconfigured)
	assert.Contains(t, err.Error(), "TLS certificate verification failed")
}

func TestUnreachableIsTransient(t *testing.T) {
	ln := listen(t)
	cfg := hostPort(t, ln.Addr().String())
	require.NoError(t, ln.Close())
	d := newTestDriver(t, cfg)

	err := d.HealthCheck(context.Background())
	require.Error(t, err)
	assert.NotErrorIs(t, err, output.ErrMisconfigured)
	assert.Contains(t, err.Error(), "syslog dial: connection refused")

	err = d.Send(context.Background(), testutil.CreateValidEvent())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func hangingServer(t *testing.T) map[string]any {
	t.Helper()
	return hostPort(t, testutil.HangingTCPServer(t))
}

func requireReturnsOnCancel(t *testing.T, call func(context.Context) error) error {
	t.Helper()
	return testutil.RequireReturnsOnCancel(t, "call", call)
}

func TestCancellation(t *testing.T) {
	t.Run("tls handshake", func(t *testing.T) {
		cfg := hangingServer(t)
		cfg["tls"] = map[string]any{"enabled": true}
		d := newTestDriver(t, cfg)
		err := requireReturnsOnCancel(t, d.HealthCheck)
		assert.NotErrorIs(t, err, output.ErrMisconfigured)
		_ = requireReturnsOnCancel(t, func(ctx context.Context) error { return d.Send(ctx, testutil.CreateValidEvent()) })
	})
	t.Run("blocked write", func(t *testing.T) {
		d := newTestDriver(t, hangingServer(t))
		require.NoError(t, d.HealthCheck(context.Background()))
		big := testutil.CreateValidEvent()
		big.OutputFields = map[string]any{"blob": strings.Repeat("x", 16<<20)}
		big.Hostname = ""
		_, err := d.message(big)
		require.NoError(t, err)
		err = requireReturnsOnCancel(t, func(ctx context.Context) error { return d.Send(ctx, big) })
		assert.True(t, errors.Is(err, context.DeadlineExceeded), err)
		assert.Contains(t, err.Error(), "timeout (deadline exceeded)")
	})
	t.Run("waiting for the connection", func(t *testing.T) {
		d := newTestDriver(t, hangingServer(t))
		d.sem <- struct{}{}
		defer d.release()
		_ = requireReturnsOnCancel(t, func(ctx context.Context) error { return d.Send(ctx, testutil.CreateValidEvent()) })
		_ = requireReturnsOnCancel(t, d.HealthCheck)
	})
}
