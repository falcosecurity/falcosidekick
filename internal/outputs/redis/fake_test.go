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

package redis

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

const replyOK = "+OK\r\n"

// fakeRedis refuses HELLO so the client falls back to RESP2 AUTH and SELECT.
type fakeRedis struct {
	replies  map[string]string
	password string
	addr     string
	commands [][]string
	mu       sync.Mutex
}

func startFakeRedis(t *testing.T, password string) *fakeRedis {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeRedis{password: password, addr: ln.Addr().String(), replies: map[string]string{}}
	var wg sync.WaitGroup
	conns := make(chan net.Conn, 64)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- conn
			wg.Go(func() { f.serve(conn) })
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for {
			select {
			case conn := <-conns:
				_ = conn.Close()
				continue
			default:
			}
			break
		}
		wg.Wait()
	})
	return f
}

// reply overrides the answer to a command, as a raw RESP line.
func (f *fakeRedis) reply(command, raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[command] = raw
}

func (f *fakeRedis) received() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.commands...)
}

// data returns the received commands, without the connection handshake.
func (f *fakeRedis) data() [][]string {
	var out [][]string
	for _, cmd := range f.received() {
		if strings.HasSuffix(cmd[0], "PUSH") || strings.HasSuffix(cmd[0], "SET") || strings.HasSuffix(cmd[0], "ADD") {
			out = append(out, cmd)
		}
	}
	return out
}

func (f *fakeRedis) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		cmd, err := readCommand(r)
		if err != nil {
			return
		}
		name := strings.ToUpper(cmd[0])
		cmd[0] = name
		f.mu.Lock()
		f.commands = append(f.commands, cmd)
		override, ok := f.replies[name]
		f.mu.Unlock()
		reply := override
		if !ok {
			reply = f.answer(cmd)
		}
		if _, err := io.WriteString(conn, reply); err != nil {
			return
		}
	}
}

func (f *fakeRedis) answer(cmd []string) string {
	switch cmd[0] {
	case "HELLO":
		return "-ERR unknown command 'HELLO'\r\n"
	case "AUTH":
		if cmd[len(cmd)-1] != f.password {
			return "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
		}
		return replyOK
	case "SELECT":
		if n, _ := strconv.Atoi(cmd[1]); n > 15 {
			return "-ERR DB index is out of range\r\n"
		}
		return replyOK
	case "PING":
		return "+PONG\r\n"
	case "XADD":
		return "$3\r\n1-0\r\n"
	case "RPUSH", "HSET":
		return ":1\r\n"
	default:
		return replyOK
	}
}

func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("unexpected %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, n)
	for i := range args {
		header, err := readLine(r)
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(strings.TrimPrefix(header, "$"))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args[i] = string(buf[:size])
	}
	return args, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}
