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

// Package e2e runs the falcosidekick binary against real or faked destinations.
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
	contentTypeJSON = "application/json"

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

// sidekick is one falcosidekick process; waitErr is valid once exited is closed.
type sidekick struct {
	waitErr error
	cmd     *exec.Cmd
	logs    *syncBuffer
	exited  chan struct{}
	// url is the ingestion listener: events, health, version, metrics.
	url string
	// apiURL is the management listener: the API and the UI.
	apiURL      string
	outputsPath string
}

// reloadOutputs rewrites the output file and sends SIGHUP.
func (s *sidekick) reloadOutputs(t *testing.T, outputs string) {
	t.Helper()
	require.NoError(t, os.WriteFile(s.outputsPath, []byte("outputs:\n"+indent(outputs)), 0o600))
	require.NoError(t, s.cmd.Process.Signal(syscall.SIGHUP))
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

// launchOptions changes the core configuration every test starts from.
type launchOptions struct {
	logLevel  string
	logFormat string
	// extra holds top-level keys absent from the default core configuration.
	extra string
	// env adds variables to the process environment.
	env []string
}

var defaultLaunch = launchOptions{logLevel: "debug", logFormat: "json"}

// startSidekick runs the binary with one retry attempt so failures surface quickly.
func startSidekick(t *testing.T, outputs string) *sidekick {
	t.Helper()
	return startSidekickWith(t, defaultLaunch, outputs)
}

func startSidekickWith(t *testing.T, core launchOptions, outputs string) *sidekick {
	t.Helper()
	s := launchSidekick(t, core, outputs)
	deadline := time.After(startTimeout)
	ready := func(url string) bool {
		path := "/readyz"
		if url == s.apiURL {
			path = "/api/v1/version"
		}
		resp, err := httpDo(http.MethodGet, url+path, nil)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	for {
		if ready(s.url) && ready(s.apiURL) {
			return s
		}
		select {
		case <-s.exited:
			t.Fatalf("falcosidekick exited during startup: %v\n%s", s.waitErr, s.logs.String())
		case <-deadline:
			t.Fatalf("falcosidekick not ready within %s\n%s", startTimeout, s.logs.String())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func startSidekickFails(t *testing.T, outputs string) string {
	t.Helper()
	return startSidekickFailsWith(t, defaultLaunch, outputs)
}

func startSidekickFailsWith(t *testing.T, core launchOptions, outputs string) string {
	t.Helper()
	s := launchSidekick(t, core, outputs)
	select {
	case <-s.exited:
	case <-time.After(startTimeout):
		t.Fatalf("falcosidekick still running after %s, want a startup failure\n%s", startTimeout, s.logs.String())
	}
	var exitErr *exec.ExitError
	require.ErrorAs(t, s.waitErr, &exitErr, "want a non-zero exit\n%s", s.logs.String())
	return s.logs.String()
}

func launchSidekick(t *testing.T, opts launchOptions, outputs string) *sidekick {
	t.Helper()
	dir := t.TempDir()
	port, managementPort := freePort(t), freePort(t)
	// No shutdown delay: tests time the shutdown itself; the drain has its own test.
	core := fmt.Sprintf(`listen_address: "127.0.0.1"
listen_port: %d
shutdown_delay: 0s
management:
  listen_port: %d
log_level: %q
log_format: %q
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
`, port, managementPort, opts.logLevel, opts.logFormat) + opts.extra
	corePath := filepath.Join(dir, "sidekick.yaml")
	outputsPath := filepath.Join(dir, "outputs.yaml")
	require.NoError(t, os.WriteFile(corePath, []byte(core), 0o600))
	require.NoError(t, os.WriteFile(outputsPath, []byte("outputs:\n"+indent(outputs)), 0o600))

	s := &sidekick{
		logs:        &syncBuffer{},
		exited:      make(chan struct{}),
		url:         fmt.Sprintf("http://127.0.0.1:%d", port),
		apiURL:      fmt.Sprintf("http://127.0.0.1:%d", managementPort),
		outputsPath: outputsPath,
	}
	s.cmd = exec.CommandContext(context.Background(), binary, "-c", corePath, "-o", outputsPath)
	s.cmd.Env = append(os.Environ(), opts.env...)
	s.cmd.Stdout, s.cmd.Stderr = s.logs, s.logs
	require.NoError(t, s.cmd.Start())
	go func() {
		s.waitErr = s.cmd.Wait()
		close(s.exited)
	}()
	t.Cleanup(func() { s.stop(t) })
	return s
}

func (s *sidekick) stop(t *testing.T) {
	t.Helper()
	select {
	case <-s.exited:
		return
	default:
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.exited:
	case <-time.After(stopTimeout):
		_ = s.cmd.Process.Kill()
		<-s.exited
		t.Errorf("falcosidekick did not stop within %s", stopTimeout)
	}
	if t.Failed() {
		t.Logf("falcosidekick logs:\n%s", s.logs.String())
	}
}

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
	Status       string `json:"status"`
	LastError    string `json:"last_error"`
	LastWarning  string `json:"last_warning"`
	SentTotal    int    `json:"sent_total"`
	FailedTotal  int    `json:"failed_total"`
	DroppedTotal int    `json:"dropped_total"`
}

func (s *sidekick) status(t *testing.T, name string) outputStatus {
	t.Helper()
	resp, err := httpDo(http.MethodGet, s.apiURL+"/api/v1/pipeline/status/"+name, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var st outputStatus
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&st))
	return st
}

func (s *sidekick) waitStatus(t *testing.T, name string, done func(outputStatus) bool) outputStatus {
	t.Helper()
	var st outputStatus
	eventuallyf(t, func() bool {
		st = s.status(t, name)
		return done(st)
	}, "status of %s: %+v", name, &st)
	return st
}

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

// httpClient has a timeout so a stuck destination fails the test instead of hanging it.
var httpClient = &http.Client{Timeout: 10 * time.Second}

func httpDo(method, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", contentTypeJSON)
	}
	return httpClient.Do(req)
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
