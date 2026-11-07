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

package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeServer is a minimal RFC 5321 server that records each session.
type fakeServer struct {
	// authReply answers the AUTH initial response; empty accepts it.
	authReply func(mechanism string, initial []byte) []string
	// rcptReply overrides the reply to RCPT TO.
	rcptReply string
	// mechanisms is the AUTH capability; empty offers PLAIN and XOAUTH2.
	mechanisms string
	tlsConfig  *tls.Config
	ln         net.Listener
	// listen is the listen address, 127.0.0.1:0 when empty.
	listen   string
	sessions []*session
	mu       sync.Mutex
	// implicitTLS wraps every accepted connection in TLS.
	implicitTLS bool
	noStartTLS  bool
	noAuth      bool
}

type session struct {
	from     string
	data     string
	commands []string
	auth     []string
	rcpt     []string
	tls      bool
	quit     bool
}

func newFakeServer(t *testing.T, configure func(*fakeServer)) *fakeServer {
	t.Helper()
	s := &fakeServer{}
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	s.tlsConfig = srv.TLS.Clone()
	s.tlsConfig.NextProtos = nil
	srv.Close()
	if configure != nil {
		configure(s)
	}
	address := s.listen
	if address == "" {
		address = "127.0.0.1:0"
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", address)
	if err != nil && s.listen != "" {
		t.Skipf("cannot listen on %s: %v", s.listen, err)
	}
	require.NoError(t, err)
	s.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

// caFile writes the certificate of the fake server, valid for 127.0.0.1.
func caFile(t *testing.T) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	return path
}

func (s *fakeServer) port() string {
	_, port, _ := net.SplitHostPort(s.ln.Addr().String())
	return port
}

// recorded returns copies of the sessions so far.
func (s *fakeServer) recorded() []session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		c := *sess
		c.commands = append([]string(nil), sess.commands...)
		c.auth = append([]string(nil), sess.auth...)
		c.rcpt = append([]string(nil), sess.rcpt...)
		out = append(out, c)
	}
	return out
}

func (s *fakeServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		sess := &session{}
		s.mu.Lock()
		s.sessions = append(s.sessions, sess)
		s.mu.Unlock()
		go s.handle(conn, sess)
	}
}

func (s *fakeServer) handle(conn net.Conn, sess *session) {
	defer func() { _ = conn.Close() }()
	update := func(f func()) {
		s.mu.Lock()
		defer s.mu.Unlock()
		f()
	}
	if s.implicitTLS {
		conn = tls.Server(conn, s.tlsConfig)
		update(func() { sess.tls = true })
	}
	r := bufio.NewReader(conn)
	reply := func(lines ...string) {
		for _, line := range lines {
			_, _ = conn.Write([]byte(line + "\r\n"))
		}
	}
	readLine := func() (string, bool) {
		line, err := r.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err == nil
	}
	reply("220 fake ESMTP")
	for {
		line, ok := readLine()
		if !ok {
			return
		}
		s.mu.Lock()
		sess.commands = append(sess.commands, line)
		s.mu.Unlock()
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			lines := []string{"250-fake"}
			if !s.noStartTLS && !sess.tls {
				lines = append(lines, "250-STARTTLS")
			}
			if !s.noAuth {
				mechanisms := s.mechanisms
				if mechanisms == "" {
					mechanisms = "PLAIN XOAUTH2"
				}
				lines = append(lines, "250-AUTH "+mechanisms)
			}
			reply(append(lines, "250 SIZE 10240000")...)
		case "STARTTLS":
			reply("220 ready")
			tlsConn := tls.Server(conn, s.tlsConfig)
			if tlsConn.HandshakeContext(context.Background()) != nil {
				return
			}
			conn = tlsConn
			r = bufio.NewReader(conn)
			update(func() { sess.tls = true })
		case "AUTH":
			mechanism, initial, _ := strings.Cut(arg, " ")
			if initial == "" {
				reply("334 ")
				initial, _ = readLine()
			}
			decoded, _ := base64.StdEncoding.DecodeString(initial)
			s.mu.Lock()
			sess.auth = append(sess.auth, mechanism+" "+string(decoded))
			s.mu.Unlock()
			var replies []string
			if s.authReply != nil {
				replies = s.authReply(mechanism, decoded)
			}
			if len(replies) == 0 {
				replies = []string{"235 2.7.0 accepted"}
			}
			for i, rep := range replies {
				reply(rep)
				if i < len(replies)-1 {
					next, _ := readLine()
					s.mu.Lock()
					sess.auth = append(sess.auth, "client: "+next)
					s.mu.Unlock()
				}
			}
		case "MAIL":
			update(func() { sess.from = arg })
			reply("250 ok")
		case "RCPT":
			if s.rcptReply != "" {
				reply(s.rcptReply)
				continue
			}
			update(func() { sess.rcpt = append(sess.rcpt, arg) })
			reply("250 ok")
		case "DATA":
			reply("354 go ahead")
			var data strings.Builder
			for {
				l, ok := readLine()
				if !ok || l == "." {
					break
				}
				_, _ = data.WriteString(strings.TrimPrefix(l, ".") + "\r\n")
			}
			s.mu.Lock()
			sess.data = data.String()
			s.mu.Unlock()
			reply("250 queued")
		case "RSET", "NOOP":
			reply("250 ok")
		case "QUIT":
			update(func() { sess.quit = true })
			reply("221 bye")
			return
		default:
			reply("502 unknown")
		}
	}
}
