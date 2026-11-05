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

//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syslogHeader is the RFC 5424 section 6 header up to MSG, with
// STRUCTURED-DATA restricted to NILVALUE:
// https://www.rfc-editor.org/rfc/rfc5424#section-6
var syslogHeader = regexp.MustCompile(`^<(\d{1,3})>1 (\S+) ([\x21-\x7e]{1,255}) ([\x21-\x7e]{1,48}) ([\x21-\x7e]{1,128}) ([\x21-\x7e]{1,32}) - `)

type syslogMessage struct {
	Time     time.Time
	Hostname string
	AppName  string
	Msg      string
	Pri      int
}

// syslogReceiver is a strict RFC 5424 receiver requiring octet counting on streams (RFC 6587 3.4.1).
type syslogReceiver struct {
	messages []syslogMessage
	rejected []string
	conns    []net.Conn
	mu       sync.Mutex
}

func (r *syslogReceiver) accept(raw string) error {
	m := syslogHeader.FindStringSubmatch(raw)
	if m == nil {
		return fmt.Errorf("not an RFC 5424 header: %.80q", raw)
	}
	pri, _ := strconv.Atoi(m[1])
	if pri > 191 || (len(m[1]) > 1 && m[1][0] == '0') {
		return fmt.Errorf("invalid PRI %s", m[1])
	}
	ts, err := time.Parse(time.RFC3339Nano, m[2])
	if err != nil {
		return fmt.Errorf("invalid TIMESTAMP %q", m[2])
	}
	if _, frac, ok := strings.Cut(strings.TrimSuffix(m[2], "Z"), "."); ok && len(frac) > 6 {
		return fmt.Errorf("TIME-SECFRAC longer than 6 digits: %q", m[2])
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, syslogMessage{Pri: pri, Time: ts, Hostname: m[3], AppName: m[4], Msg: raw[len(m[0]):]})
	return nil
}

func (r *syslogReceiver) reject(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected = append(r.rejected, reason)
}

func (r *syslogReceiver) snapshot() (messages []syslogMessage, rejected []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]syslogMessage(nil), r.messages...), append([]string(nil), r.rejected...)
}

// closeConnections closes every stream accepted so far, like a receiver restart.
func (r *syslogReceiver) closeConnections() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conns {
		_ = c.Close()
	}
	r.conns = nil
}

func (r *syslogReceiver) connections() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

func (r *syslogReceiver) serveStream(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		r.conns = append(r.conns, conn)
		r.mu.Unlock()
		go r.readFrames(conn)
	}
}

func (r *syslogReceiver) readFrames(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	for {
		length, err := br.ReadString(' ')
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				r.reject("read: " + err.Error())
			}
			return
		}
		digits := strings.TrimSuffix(length, " ")
		n, err := strconv.Atoi(digits)
		if err != nil || n <= 0 || digits[0] == '0' {
			r.reject(fmt.Sprintf("invalid MSG-LEN %.20q", digits))
			return
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(br, frame); err != nil {
			r.reject("short frame")
			return
		}
		if err := r.accept(string(frame)); err != nil {
			r.reject(err.Error())
			return
		}
	}
}

func (r *syslogReceiver) servePackets(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if err := r.accept(string(buf[:n])); err != nil {
			r.reject(err.Error())
		}
	}
}

func startSyslogReceiver(t *testing.T, protocol string) (receiver *syslogReceiver, port int, caFile string) {
	t.Helper()
	receiver = &syslogReceiver{}
	lc := net.ListenConfig{}
	if protocol == "udp" {
		pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })
		go receiver.servePackets(pc)
		return receiver, pc.LocalAddr().(*net.UDPAddr).Port, ""
	}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port = ln.Addr().(*net.TCPAddr).Port
	if protocol == "tls" {
		// The httptest certificate is valid for 127.0.0.1.
		srv := httptest.NewUnstartedServer(nil)
		srv.StartTLS()
		cfg := srv.TLS.Clone()
		cfg.NextProtos = nil
		caFile = filepath.Join(t.TempDir(), "syslog-ca.pem")
		require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
		srv.Close()
		ln = tls.NewListener(ln, cfg)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		receiver.closeConnections()
	})
	go receiver.serveStream(ln)
	return receiver, port, caFile
}

func syslogOutput(port int, protocol, extra string) string {
	return fmt.Sprintf("syslog:\n  host: 127.0.0.1\n  port: %d\n  protocol: %s\n", port, protocol) + indent(extra)
}

func waitSyslog(t *testing.T, r *syslogReceiver, marker string) syslogMessage {
	t.Helper()
	var found syslogMessage
	eventuallyf(t, func() bool {
		messages, _ := r.snapshot()
		for _, m := range messages {
			if strings.Contains(m.Msg, marker) {
				found = m
				return true
			}
		}
		return false
	}, "syslog message with %s", marker)
	return found
}

func TestSyslogDeliversEvent(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp", "tls"} {
		t.Run(protocol, func(t *testing.T) {
			receiver, port, caFile := startSyslogReceiver(t, protocol)
			extra := ""
			if caFile != "" {
				extra = fmt.Sprintf("tls:\n  ca_file: %q\n", caFile)
			}
			sk := startSidekick(t, syslogOutput(port, protocol, extra))
			marker := newMarker(t)
			sk.postEvent(t, marker)

			m := waitSyslog(t, receiver, marker)
			assert.Equal(t, 16*8+4, m.Pri, "local0.warning")
			assert.Equal(t, "e2e-host", m.Hostname)
			assert.Equal(t, "falco", m.AppName)
			assert.WithinDuration(t, time.Now(), m.Time, time.Minute)
			var payload map[string]any
			require.NoError(t, json.Unmarshal([]byte(m.Msg), &payload))
			assert.Equal(t, "E2E "+marker, payload["rule"])
			assert.Equal(t, "warning", payload["priority"])
			assert.Equal(t, marker, payload["output_fields"].(map[string]any)["e2e.marker"])

			st := sk.waitStatus(t, "syslog", func(st outputStatus) bool { return st.SentTotal == 1 })
			assert.Zero(t, st.FailedTotal)
			_, rejected := receiver.snapshot()
			assert.Empty(t, rejected)
		})
	}
}

func TestSyslogCEF(t *testing.T) {
	receiver, port, _ := startSyslogReceiver(t, "tcp")
	sk := startSidekick(t, syslogOutput(port, "tcp", "format: cef\nfacility: auth\n"))
	marker := newMarker(t)
	sk.postEvent(t, marker)

	m := waitSyslog(t, receiver, marker)
	assert.Equal(t, 4*8+4, m.Pri, "auth.warning")
	assert.Regexp(t, `^CEF:0\|Falcosecurity\|Falco\|1\.0\|Falco Event\|E2E `+marker+`\|6\|uuid=\S+ start=\S+ msg=e2e event `+marker+
		` source=syscall hostname=e2e-host outputfields=e2e\.marker:`+marker+` proc\.name:e2e tags=e2e$`, m.Msg)
	_, rejected := receiver.snapshot()
	assert.Empty(t, rejected)
}

func TestSyslogReconnects(t *testing.T) {
	receiver, port, _ := startSyslogReceiver(t, "tcp")
	sk := startSidekick(t, syslogOutput(port, "tcp", ""))
	first := newMarker(t)
	sk.postEvent(t, first)
	waitSyslog(t, receiver, first)
	require.Equal(t, 1, receiver.connections(), "the health check connection serves delivery")

	receiver.closeConnections()
	time.Sleep(100 * time.Millisecond)
	second := newMarker(t)
	sk.postEvent(t, second)
	waitSyslog(t, receiver, second)
	st := sk.waitStatus(t, "syslog", func(st outputStatus) bool { return st.SentTotal == 2 })
	assert.Zero(t, st.FailedTotal)
	assert.Equal(t, 1, receiver.connections())
}

func TestSyslogUnknownCAStopsStartup(t *testing.T) {
	_, port, _ := startSyslogReceiver(t, "tls")
	logs := startSidekickFails(t, syslogOutput(port, "tls", fmt.Sprintf("tls:\n  ca_file: %q\n", writeUnknownCA(t))))
	assert.Contains(t, logs, "health check")
	assert.Contains(t, logs, "TLS certificate verification failed")
}

func TestSyslogReportsUnreachableReceiver(t *testing.T) {
	sk := startSidekick(t, syslogOutput(freePort(t), "tcp", ""))
	st := sk.status(t, "syslog")
	assert.Equal(t, "degraded", st.Status, "an unreachable receiver at startup is transient")
	assert.Contains(t, st.LastWarning, "connection refused")

	sk.postEvent(t, newMarker(t))
	st = sk.waitStatus(t, "syslog", func(st outputStatus) bool { return st.FailedTotal == 1 })
	assert.Zero(t, st.SentTotal)
	assert.Contains(t, st.LastError, "syslog dial: connection refused")
}
