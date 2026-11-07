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

package shared_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"cloud.google.com/go/pubsub/v2/pstest"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kmsg"
	"google.golang.org/grpc"
)

// echoedSecret is the configured secret and the text every hostile destination echoes back.
const echoedSecret = "ECHOED-SECRET-SENTINEL"

const sqsBatchTarget = "AmazonSQS.SendMessageBatch"

// fakeDestination is a destination under the test's control: host is what the output's config receives,
// attempts counts the deliveries it answered.
type fakeDestination struct {
	host     string
	attempts atomic.Int32
}

// hostileHeaders echoes the secret in every header a client reads, including the target of a redirect.
func hostileHeaders(h http.Header) {
	h.Set("Content-Type", "application/json")
	h.Set("WWW-Authenticate", `Bearer realm="`+echoedSecret+`", error_description="`+echoedSecret+`"`)
	h.Set("X-Request-Id", echoedSecret)
	h.Set("X-Amzn-Errortype", echoedSecret)
	h.Set("X-Amz-Request-Id", echoedSecret)
	h.Set("X-Amz-Id-2", echoedSecret)
	h.Set("Location", "http://"+echoedSecret+".invalid/"+echoedSecret)
}

func hostileHTTPServer(t *testing.T, code int, body string) *fakeDestination {
	t.Helper()
	return hostileHandlerServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	})
}

// hostileHandlerServer counts each request, drains it and sets the hostile headers before answer runs.
func hostileHandlerServer(t *testing.T, answer http.HandlerFunc) *fakeDestination {
	t.Helper()
	d := &fakeDestination{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.attempts.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		hostileHeaders(w.Header())
		answer(w, r)
	}))
	t.Cleanup(server.Close)
	d.host = server.URL
	return d
}

// hostileGRPCServer fails every RPC with rpcErr.
func hostileGRPCServer(t *testing.T, rpcErr error) *fakeDestination {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	d := &fakeDestination{host: "http://" + ln.Addr().String()}
	server := grpc.NewServer(grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error {
		d.attempts.Add(1)
		return rpcErr
	}))
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(server.Stop)
	return d
}

// statusReactor answers every call of one pstest method with err and counts the calls.
type statusReactor struct {
	err      error
	attempts *atomic.Int32
}

func (r statusReactor) React(any) (handled bool, ret any, err error) {
	r.attempts.Add(1)
	return true, nil, r.err
}

// hostilePubSubServer fails Publish and GetTopic with rpcErr.
func hostilePubSubServer(t *testing.T, rpcErr error) *fakeDestination {
	t.Helper()
	d := &fakeDestination{}
	refuse := statusReactor{err: rpcErr, attempts: &d.attempts}
	server := pstest.NewServer(
		pstest.ServerReactorOption{FuncName: "Publish", Reactor: refuse},
		pstest.ServerReactorOption{FuncName: "GetTopic", Reactor: refuse},
	)
	t.Cleanup(func() { _ = server.Close() })
	d.host = server.Addr
	return d
}

// hostileTCPServer runs serve on each connection and closes every connection when the test ends.
func hostileTCPServer(t *testing.T, serve func(conn net.Conn)) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				serve(conn)
			})
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-stopped
		mu.Lock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String()
}

func hostileSMTPConfig(h string, auth map[string]any) map[string]any {
	cfg := hostPort(h)
	maps.Copy(cfg, map[string]any{"from": "sender@example.com", "to": []string{"rcpt@example.com"}, "tls_mode": "none"})
	maps.Copy(cfg, auth)
	return cfg
}

// hostileSMTPServer greets, answers every command but QUIT with reply, and echoes the secret in each of its own lines.
func hostileSMTPServer(t *testing.T, reply func(verb string) []string) string {
	t.Helper()
	return hostileTCPServer(t, func(conn net.Conn) {
		write := func(lines ...string) bool {
			for _, line := range lines {
				if _, err := io.WriteString(conn, line+"\r\n"); err != nil {
					return false
				}
			}
			return true
		}
		if !write("220 hostile ESMTP " + echoedSecret) {
			return
		}
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			verb, _, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			if verb = strings.ToUpper(verb); verb == "QUIT" {
				write("221 " + echoedSecret)
				return
			}
			if !write(reply(verb)...) {
				return
			}
		}
	})
}

// hostileRESPServer refuses HELLO like a RESP2 server and answers every other command, AUTH included, with reply.
func hostileRESPServer(t *testing.T, reply func(command string) string) string {
	t.Helper()
	return hostileTCPServer(t, func(conn net.Conn) {
		r := bufio.NewReader(conn)
		for {
			command, err := readRESPCommand(r)
			if err != nil {
				return
			}
			answer := reply(command)
			if command == "HELLO" {
				answer = "-ERR unknown command 'HELLO'\r\n"
			}
			if _, err := io.WriteString(conn, answer); err != nil {
				return
			}
		}
	})
}

// readRESPCommand reads one array of bulk strings and returns its first element in upper case.
func readRESPCommand(r *bufio.Reader) (string, error) {
	header, err := readRESPLine(r)
	if err != nil {
		return "", err
	}
	count, err := strconv.Atoi(strings.TrimPrefix(header, "*"))
	if err != nil {
		return "", err
	}
	var command string
	for i := range count {
		header, err := readRESPLine(r)
		if err != nil {
			return "", err
		}
		size, err := strconv.Atoi(strings.TrimPrefix(header, "$"))
		if err != nil {
			return "", err
		}
		arg := make([]byte, size+2)
		if _, err := io.ReadFull(r, arg); err != nil {
			return "", err
		}
		if i == 0 {
			command = strings.ToUpper(string(arg[:size]))
		}
	}
	return command, nil
}

func readRESPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// hostileKafkaBroker frames the protocol: it advertises supported in every ApiVersions answer and
// passes every other request, unparsed beyond its header, to respond; a nil answer closes the connection.
func hostileKafkaBroker(
	t *testing.T, supported []kmsg.ApiVersionsResponseApiKey, respond func(conn net.Conn, req kmsg.Request) kmsg.Response,
) string {
	t.Helper()
	return hostileTCPServer(t, func(conn net.Conn) {
		for {
			var size [4]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				return
			}
			frame := make([]byte, binary.BigEndian.Uint32(size[:]))
			if _, err := io.ReadFull(conn, frame); err != nil || len(frame) < 8 {
				return
			}
			key, version := int16(binary.BigEndian.Uint16(frame)), int16(binary.BigEndian.Uint16(frame[2:]))
			req := kmsg.RequestForKey(key)
			if req == nil {
				return
			}
			req.SetVersion(version)
			var resp kmsg.Response
			if _, ok := req.(*kmsg.ApiVersionsRequest); ok {
				versions := kmsg.NewPtrApiVersionsResponse()
				versions.ApiKeys = supported
				resp = versions
			} else if resp = respond(conn, req); resp == nil {
				return
			}
			resp.SetVersion(version)
			out := append([]byte{0, 0, 0, 0}, frame[4:8]...)
			if _, apiVersions := resp.(*kmsg.ApiVersionsResponse); resp.IsFlexible() && !apiVersions {
				out = append(out, 0) // the ApiVersions response header is never flexible
			}
			out = resp.AppendTo(out)
			binary.BigEndian.PutUint32(out, uint32(len(out)-4))
			if _, err := conn.Write(out); err != nil {
				return
			}
		}
	})
}
