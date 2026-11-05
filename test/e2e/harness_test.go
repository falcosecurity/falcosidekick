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

// Package e2e runs the falcosidekick binary against real or faked
// destinations: a Falco event goes in over HTTP and each test checks what
// the destination received through the destination's own API.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	startTimeout   = 20 * time.Second
	stopTimeout    = 20 * time.Second
	deliverTimeout = 30 * time.Second
)

var binary string

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(m *testing.M) (int, error) {
	if bin := os.Getenv("FALCOSIDEKICK_E2E_BIN"); bin != "" {
		binary = bin
		return m.Run(), nil
	}
	dir, err := os.MkdirTemp("", "falcosidekick-e2e")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	binary = filepath.Join(dir, "falcosidekick")
	build := exec.CommandContext(context.Background(), "go", "build", "-o", binary, "../../cmd/falcosidekick")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		return 0, fmt.Errorf("build falcosidekick: %w", err)
	}
	return m.Run(), nil
}

// sidekick is one running falcosidekick process.
type sidekick struct {
	cmd  *exec.Cmd
	logs *syncBuffer
	url  string
}

type syncBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
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

// startSidekick runs the binary with one retry attempt so failures surface
// quickly, and outputs given as the YAML body under `outputs:`.
func startSidekick(t *testing.T, outputs string) *sidekick {
	t.Helper()
	dir := t.TempDir()
	port := freePort(t)
	core := fmt.Sprintf(`listen_address: "127.0.0.1"
listen_port: %d
log_level: debug
log_format: json
runtime_defaults:
  queue_size: 100
  workers: 1
  retry:
    max_attempts: 1
    initial_interval: 100ms
    max_interval: 100ms
    multiplier: 1
  circuit_breaker:
    failure_threshold: 100
    success_threshold: 1
    reset_timeout: 1s
`, port)
	corePath := filepath.Join(dir, "sidekick.yaml")
	outputsPath := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(corePath, []byte(core), 0o600))
	require.NoError(t, os.WriteFile(outputsPath, []byte("outputs:\n"+indent(outputs)), 0o600))

	s := &sidekick{logs: &syncBuffer{}, url: fmt.Sprintf("http://127.0.0.1:%d", port)}
	s.cmd = exec.CommandContext(context.Background(), binary, "-c", corePath, "-o", outputsPath)
	s.cmd.Stdout, s.cmd.Stderr = s.logs, s.logs
	require.NoError(t, s.cmd.Start())
	t.Cleanup(func() { s.stop(t) })

	deadline := time.Now().Add(startTimeout)
	for time.Now().Before(deadline) {
		resp, err := httpDo(http.MethodGet, s.url+"/healthz", nil)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("falcosidekick not ready within %s\n%s", startTimeout, s.logs.String())
	return nil
}

func (s *sidekick) stop(t *testing.T) {
	t.Helper()
	if s.cmd.ProcessState != nil {
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(stopTimeout):
		_ = s.cmd.Process.Kill()
		<-done
		t.Errorf("falcosidekick did not stop within %s", stopTimeout)
	}
	if t.Failed() {
		t.Logf("falcosidekick logs:\n%s", s.logs.String())
	}
}

// postEvent sends a Falco event carrying marker in its output fields and rule.
func (s *sidekick) postEvent(t *testing.T, marker string) {
	t.Helper()
	body, err := json.Marshal(falcoEvent(marker))
	require.NoError(t, err)
	resp, err := httpDo(http.MethodPost, s.url+"/", body)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func falcoEvent(marker string) map[string]any {
	return map[string]any{
		"time":     time.Now().UTC().Format(time.RFC3339Nano),
		"rule":     "E2E " + marker,
		"priority": "Warning",
		"source":   "syscall",
		"hostname": "e2e-host",
		"output":   "e2e event " + marker,
		"tags":     []string{"e2e"},
		"output_fields": map[string]any{
			"e2e.marker": marker,
			"proc.name":  "e2e",
		},
	}
}

type outputStatus struct {
	LastError    string `json:"last_error"`
	SentTotal    int    `json:"sent_total"`
	FailedTotal  int    `json:"failed_total"`
	DroppedTotal int    `json:"dropped_total"`
}

func (s *sidekick) status(t *testing.T, name string) outputStatus {
	t.Helper()
	resp, err := httpDo(http.MethodGet, s.url+"/api/v1/pipeline/status/"+name, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var st outputStatus
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&st))
	return st
}

// waitStatus polls the output status until done reports true.
func (s *sidekick) waitStatus(t *testing.T, name string, done func(outputStatus) bool) outputStatus {
	t.Helper()
	var st outputStatus
	eventuallyf(t, func() bool {
		st = s.status(t, name)
		return done(st)
	}, "status of %s: %+v", name, &st)
	return st
}

// eventuallyf polls cond until it holds or deliverTimeout passes.
func eventuallyf(t *testing.T, cond func() bool, format string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	defer cancel()
	for {
		if cond() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("condition not met within %s: "+format, append([]any{deliverTimeout}, args...)...)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func newMarker(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

func requireEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("%s not set", name)
	}
	return value
}

// httpDo sends a request with a JSON body when body is not nil.
func httpDo(method, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

func freePort(t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n") + "\n"
}
