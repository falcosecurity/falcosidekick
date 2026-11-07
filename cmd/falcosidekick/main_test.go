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

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/api"
	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/metrics"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
	"github.com/falcosecurity/falcosidekick/internal/pipeline"
	"github.com/falcosecurity/falcosidekick/internal/version"
	"github.com/falcosecurity/falcosidekick/ui"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sidekick.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

// writeServerConfig writes a core file with free ingestion and management ports on 127.0.0.1, then extra.
func writeServerConfig(t *testing.T, extra string) (path string, port, managementPort int) {
	t.Helper()
	port, managementPort = findFreePort(t), findFreePort(t)
	path = writeTestConfig(t, fmt.Sprintf(
		"listen_port: %d\nlisten_address: 127.0.0.1\nmanagement:\n  listen_port: %d\n%s", port, managementPort, extra))
	return path, port, managementPort
}

func writeTestOutputs(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "outputs.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func findFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper, ephemeral listener
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

func waitForServer(t *testing.T, port int) {
	t.Helper()
	const timeout = 5 * time.Second
	deadline := time.Now().Add(timeout)
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL) //nolint:noctx // test helper, hardcoded localhost
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server on port %d did not become ready within %s", port, timeout)
}

func writeTestOutputsAt(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestRunStringSliceFlag(t *testing.T) {
	var f stringSliceFlag
	require.NoError(t, f.Set("a"))
	require.NoError(t, f.Set("b"))
	assert.Equal(t, "a,b", f.String())
	assert.Len(t, f, 2)
}

func TestMainVersionFlag(t *testing.T) {
	if os.Getenv("FALCOSIDEKICK_TEST_MAIN_VERSION") == "1" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		flag.CommandLine.SetOutput(io.Discard)
		os.Args = []string{"falcosidekick", "-version"}
		main()
		return
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=TestMainVersionFlag")
	cmd.Env = append(os.Environ(), "FALCOSIDEKICK_TEST_MAIN_VERSION=1")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	require.NoError(t, cmd.Run(), "stderr: %s", stderr.String())
	assert.Contains(t, stdout.String(), "falcosidekick ")
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriteVersion(t *testing.T) {
	info := version.Info{Version: "v3", Commit: "abc", BuildDate: "today", GoVersion: "go1.26.10"}

	var out bytes.Buffer
	require.NoError(t, writeVersion(&out, info))
	assert.Equal(t, "falcosidekick v3 (commit: abc, built: today, go: go1.26.10)\n", out.String())

	writeErr := errors.New("broken pipe")
	require.ErrorIs(t, writeVersion(failingWriter{err: writeErr}, info), writeErr)
}

func TestMainFailurePaths(t *testing.T) {
	const scenarioEnv = "FALCOSIDEKICK_TEST_MAIN_FAILURE"
	scenarios := map[string]func(t *testing.T){
		"version with closed stdout": func(t *testing.T) {
			require.NoError(t, os.Stdout.Close())
			os.Args = []string{"falcosidekick", "-version"}
			main()
		},
		"invalid config path": func(*testing.T) {
			os.Args = []string{"falcosidekick", "-c", "/nonexistent/config.yaml"}
			main()
		},
		"fatal after slog default replaced": func(*testing.T) {
			slog.SetDefault(slog.New(slog.NewJSONHandler(io.Discard, nil)))
			fatal(errors.New("boom"))
		},
	}

	if name := os.Getenv(scenarioEnv); name != "" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		flag.CommandLine.SetOutput(io.Discard)
		scenarios[name](t)
		return
	}

	tests := []struct {
		name       string
		wantPrefix string
	}{
		{name: "version with closed stdout", wantPrefix: "fatal: write version: "},
		{name: "invalid config path", wantPrefix: "fatal: config load"},
		{name: "fatal after slog default replaced", wantPrefix: "fatal: boom\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMainFailurePaths$")
			cmd.Env = append(os.Environ(), scenarioEnv+"="+tc.name)

			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			var exitErr *exec.ExitError
			require.ErrorAs(t, cmd.Run(), &exitErr)
			assert.Equal(t, 1, exitErr.ExitCode())
			assert.True(t, strings.HasPrefix(stderr.String(), tc.wantPrefix), "stderr: %q", stderr.String())
		})
	}
}

func TestMainStartupFailureNeverEchoesOutputValues(t *testing.T) {
	const (
		outputsEnv = "FALCOSIDEKICK_TEST_MAIN_OUTPUTS"
		sentinel   = "s3cret-sentinel"
	)
	if path := os.Getenv(outputsEnv); path != "" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		flag.CommandLine.SetOutput(io.Discard)
		os.Args = []string{"falcosidekick", "-o", path}
		main()
		return
	}

	outputs := writeTestOutputs(t, `
outputs:
  webhook:
    host: "https://u:`+sentinel+`@ho st/x"
`)
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMainStartupFailureNeverEchoesOutputValues$")
	cmd.Env = append(os.Environ(), outputsEnv+"="+outputs)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	var exitErr *exec.ExitError
	require.ErrorAs(t, cmd.Run(), &exitErr, "stderr: %s", stderr.String())
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Contains(t, stderr.String(), "fatal: ")
	assert.Contains(t, stderr.String(), "host: invalid URL")
	assert.NotContains(t, stderr.String()+stdout.String(), sentinel)
}

func TestRunRejectsRemovedTargetFields(t *testing.T) {
	const sentinel = "s3cret-sentinel"
	outputs := writeTestOutputs(t, "outputs:\n  webhook:\n    url: https://h/"+sentinel+"\n")
	err := run(context.Background(), "", []string{outputs})
	require.ErrorContains(t, err, "unknown keys: url")
	assert.NotContains(t, err.Error(), sentinel)
}

func TestRunInvalidConfigPath(t *testing.T) {
	err := run(context.Background(), "/nonexistent/config.yaml", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config load")
}

func TestRunInvalidOutputPath(t *testing.T) {
	cfg := writeTestConfig(t, "{}")
	err := run(context.Background(), cfg, []string{"/nonexistent/outputs.yaml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outputs load")
}

func TestRunConfigValidationFailure(t *testing.T) {
	cfg := writeTestConfig(t, "listen_port: -1")
	err := run(context.Background(), cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config validation")
}

func TestRunUnknownOutputType(t *testing.T) {
	cfg := writeTestConfig(t, "{}")
	outs := writeTestOutputs(t, `
outputs:
  nonexistent_output:
    host: "http://example.com"
`)
	err := run(context.Background(), cfg, []string{outs})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent_output")
}

func TestRunSecretResolutionFailure(t *testing.T) {
	cfg := writeTestConfig(t, "{}")
	outs := writeTestOutputs(t, `
outputs:
  webhook:
    host: "http://example.com"
    password_file: /nonexistent/secret
`)
	err := run(context.Background(), cfg, []string{outs})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret resolution")
}

func TestRunUnknownCoreConfigKey(t *testing.T) {
	cfg := writeTestConfig(t, "listen_portt: 3000")
	err := run(context.Background(), cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen_portt")
}

func TestCreateDatabaseInMemory(t *testing.T) {
	db, err := createDatabase(t.Context(), &core.DatabaseConfig{Backend: core.DatabaseInMemory, ConnectTimeout: time.Second})
	require.NoError(t, err)
	require.NotNil(t, db)
	assert.NoError(t, db.Close())
}

func TestCreateDatabaseUnknownBackend(t *testing.T) {
	_, err := createDatabase(t.Context(), &core.DatabaseConfig{Backend: "unknown", ConnectTimeout: time.Second})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func loadDefaultConfigForCmdTest(t *testing.T) *config.Config {
	t.Helper()
	cfgPath := writeTestConfig(t, "{}")
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	return cfg
}

func TestCreateOutputsCreateFailure(t *testing.T) {
	cfg := loadDefaultConfigForCmdTest(t)

	cat, err := catalog.New([]output.Type{
		{
			Name:   "good",
			Schema: output.Schema{},
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{
					DriverName: "good",
				}, nil
			},
		},
		{
			Name:   "broken",
			Schema: output.Schema{},
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return nil, errors.New("create failed")
			},
		},
	})
	require.NoError(t, err)

	_, err = createOutputs(context.Background(), cfg, map[string]map[string]any{
		"good":   {},
		"broken": {},
	}, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `output "broken"`)
}

func TestCreateOutputsInitFailure(t *testing.T) {
	cfg := loadDefaultConfigForCmdTest(t)

	cat, err := catalog.New([]output.Type{
		{
			Name:   "good",
			Schema: output.Schema{},
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{
					DriverName: "good",
				}, nil
			},
		},
		{
			Name:   "initfail",
			Schema: output.Schema{},
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{
					DriverName: "initfail",
					InitFunc: func(context.Context) error {
						return errors.New("init failed")
					},
				}, nil
			},
		},
	})
	require.NoError(t, err)

	_, err = createOutputs(context.Background(), cfg, map[string]map[string]any{
		"good":     {},
		"initfail": {},
	}, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `output "initfail": init:`)
}

func TestRestoreFromDB_BuildsFromProvisionedFalseEntries(t *testing.T) {
	ctx := context.Background()
	cfg := loadDefaultConfigForCmdTest(t)

	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "address", Type: "string"}}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)

	db := database.NewMemory()
	// UI-only output left by a previous run.
	_, err = db.SaveOutputConfig(ctx, "webhook", 0, map[string]any{"address": "http://sink"})
	require.NoError(t, err)

	fileOutputs := map[string]map[string]any{}
	restored, err := restoreFromDB(ctx, cfg, db, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), fileOutputs)
	require.NoError(t, err)
	outs, failures := restored.outputs, restored.failures
	require.Empty(t, failures)
	require.Len(t, outs, 1, "UI-only entry must be rebuilt into a live Output on startup")
	assert.Equal(t, "webhook", outs[0].Name())

	for _, o := range outs {
		_ = o.Close()
	}
}

// The store keeps secret file references; a restart reads the files again to build the outputs.
func TestRestoreFromDB_ReadsStoredSecretFiles(t *testing.T) {
	ctx := context.Background()
	cfg := loadDefaultConfigForCmdTest(t)
	secret := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(secret, []byte("from-file\n"), 0o600))

	var built map[string]any
	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "token", Type: "string", Secret: true}}},
		New: func(raw map[string]any, _ output.Deps) (output.Driver, error) {
			built = raw
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)
	db := database.NewMemory()
	_, err = db.SaveOutputConfig(ctx, "webhook", 0, map[string]any{"token_file": secret})
	require.NoError(t, err)

	restored, err := restoreFromDB(ctx, cfg, db, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), nil)
	require.NoError(t, err)
	outs, failures := restored.outputs, restored.failures
	require.Empty(t, failures)
	require.Len(t, outs, 1)
	t.Cleanup(func() { _ = outs[0].Close() })
	assert.Equal(t, map[string]any{"token": "from-file"}, built)
	assert.Equal(t, map[string]map[string]any{"webhook": {"token": "from-file"}}, restored.resolved,
		"the reloader gets the resolved config to see a later rotation")
	stored, err := db.GetOutputConfig(ctx, "webhook")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"token_file": secret}, stored.Config, "restore never writes the secret back")
}

// One broken stored output must not keep Sidekick or the other stored outputs from starting.
func TestRestoreFromDB_LeavesOutUnbuildableOutputsAndKeepsTheirRows(t *testing.T) {
	ctx := context.Background()
	cfg := loadDefaultConfigForCmdTest(t)
	mockType := func(name string, build error) output.Type {
		return output.Type{
			Name:   name,
			Schema: output.Schema{Fields: []output.SchemaField{{Name: "token", Type: "string", Secret: true}}},
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				if build != nil {
					return nil, build
				}
				return &testutil.MockDriver{DriverName: name}, nil
			},
		}
	}
	cat, err := catalog.New([]output.Type{
		mockType("webhook", nil),
		mockType("slack", nil),
		mockType("loki", errors.New("invalid host")),
	})
	require.NoError(t, err)
	db := database.NewMemory()
	stored := map[string]map[string]any{
		"webhook": {"token": "ok"},
		"slack":   {"token_file": filepath.Join(t.TempDir(), "missing")},
		"loki":    {"token": "ok"},
		"retired": {"address": "http://x"},
	}
	for name, c := range stored {
		_, err := db.SaveOutputConfig(ctx, name, 0, c)
		require.NoError(t, err)
	}

	restored, err := restoreFromDB(ctx, cfg, db, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), nil)
	require.NoError(t, err)
	outs, failures := restored.outputs, restored.failures
	require.Len(t, outs, 1)
	t.Cleanup(func() { _ = outs[0].Close() })
	assert.Equal(t, "webhook", outs[0].Name())
	assert.ElementsMatch(t, []string{"slack", "loki", "retired"}, slices.Collect(maps.Keys(failures)))
	assert.ErrorContains(t, failures["loki"], "invalid host")

	entries, err := db.GetOutputConfigs(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 4, "rows of outputs that did not start are kept")
}

func TestRestoreFromDB_SkipsProvisionedEntries(t *testing.T) {
	ctx := context.Background()
	cfg := loadDefaultConfigForCmdTest(t)

	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "address", Type: "string"}}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)

	db := database.NewMemory()
	require.NoError(t, db.Provision(ctx, &core.ProvisionRequest{
		Outputs: map[string]map[string]any{"webhook": {"address": "http://from-file"}},
	}))
	// The file already built webhook, so restore must skip it.
	fileOutputs := map[string]map[string]any{"webhook": {"address": "http://from-file"}}
	restored, err := restoreFromDB(ctx, cfg, db, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), fileOutputs)
	require.NoError(t, err)
	outs, failures := restored.outputs, restored.failures
	require.Empty(t, failures)
	assert.Empty(t, outs, "provisioned entries must not be rebuilt by the UI-only restore path")
}

func TestCreateOutputsRuntimeConfigFailure(t *testing.T) {
	cfg := loadDefaultConfigForCmdTest(t)

	cat, err := catalog.New([]output.Type{
		{
			Name:   "good",
			Schema: output.Schema{},
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{
					DriverName: "good",
				}, nil
			},
		},
		{
			Name:   "badcfg",
			Schema: output.Schema{},
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{
					DriverName: "badcfg",
					RuntimeConfigFunc: func() output.RuntimeConfig {
						return output.RuntimeConfig{
							MinPriority: event.Priority("not-a-priority"),
						}
					},
				}, nil
			},
		},
	})
	require.NoError(t, err)

	_, err = createOutputs(context.Background(), cfg, map[string]map[string]any{
		"good":   {},
		"badcfg": {},
	}, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `output "badcfg": runtime merge:`)
}

func TestRunNegativePollInterval(t *testing.T) {
	cfg := writeTestConfig(t, "reload:\n  poll_interval: -1s")
	err := run(context.Background(), cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config validation")
}

func TestRunUIEnabledMissingEventSource(t *testing.T) {
	cfg := writeTestConfig(t, "ui:\n  enabled: true\n  event_source: nonexistent")
	outs := writeTestOutputs(t, "outputs:\n  webhook:\n    host: http://localhost:9999\n")
	err := run(context.Background(), cfg, []string{outs})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ui.event_source: output not found or does not implement ReadableStore")
	assert.NotContains(t, err.Error(), "nonexistent")
}

func TestRunLifecycleCleanShutdown(t *testing.T) {
	cfg, port, _ := writeServerConfig(t, "")
	outs := writeTestOutputs(t, "outputs:\n  webhook:\n    host: http://127.0.0.1:19999\n")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, []string{outs})
	}()

	waitForServer(t, port)

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err, "clean shutdown must return nil")
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not exit within 15 seconds of context cancel")
	}
}

func TestRunServerStartFailure(t *testing.T) {
	// Occupy a port so the server cannot bind.
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper, ephemeral listener
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	defer func() { _ = ln.Close() }()

	cfg := writeTestConfig(t, fmt.Sprintf("listen_port: %d\nlisten_address: 127.0.0.1\nmanagement:\n  listen_port: %d",
		port, findFreePort(t)))
	outs := writeTestOutputs(t, "outputs:\n  webhook:\n    host: http://127.0.0.1:19999\n")

	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfg, []string{outs})
	}()

	select {
	case err := <-done:
		require.Error(t, err, "server bind failure must propagate as error")
		assert.Contains(t, err.Error(), "server")
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not exit within 15 seconds after server bind failure")
	}
}

func TestRunSIGHUPReload(t *testing.T) {
	cfg, port, _ := writeServerConfig(t, "")
	outs := writeTestOutputs(t, "outputs:\n  webhook:\n    host: http://127.0.0.1:19999\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, []string{outs})
	}()

	waitForServer(t, port)

	// Drain any pending SIGHUP from prior tests by briefly registering our own channel.
	drain := make(chan os.Signal, 1)
	signal.Notify(drain, syscall.SIGHUP)
	signal.Stop(drain)

	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGHUP))

	time.Sleep(300 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err, "clean shutdown after SIGHUP must return nil")
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not exit within 15 seconds")
	}
}

func TestRunPollerDetectsChange(t *testing.T) {
	cfg, port, _ := writeServerConfig(t, "reload:\n  poll_interval: 100ms")

	dir := t.TempDir()
	outsPath := filepath.Join(dir, "outputs.yaml")
	writeTestOutputsAt(t, outsPath, "outputs:\n  webhook:\n    host: http://127.0.0.1:19999\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, []string{outsPath})
	}()

	waitForServer(t, port)

	writeTestOutputsAt(t, outsPath, "outputs:\n  webhook:\n    host: http://127.0.0.1:29999\n")

	// Covers one 100ms poller tick plus processing.
	time.Sleep(400 * time.Millisecond)

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err, "clean shutdown after poller reload must return nil")
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not exit within 15 seconds")
	}
}

func TestRunPollDisabledCleanShutdown(t *testing.T) {
	cfg, port, _ := writeServerConfig(t, "reload:\n  poll_interval: 0s")
	outs := writeTestOutputs(t, "outputs:\n  webhook:\n    host: http://127.0.0.1:19999\n")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, []string{outs})
	}()

	waitForServer(t, port)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err, "clean shutdown with poller disabled must return nil")
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not exit within 15 seconds of context cancel")
	}
}

func TestRunNoOutputPathsCleanShutdown(t *testing.T) {
	cfg, port, _ := writeServerConfig(t, "")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, nil)
	}()

	waitForServer(t, port)

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err, "clean shutdown with no output paths must return nil")
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not exit within 15 seconds of context cancel")
	}
}

func TestAppServePropagatesStartError(t *testing.T) {
	// Occupy the port so srv.Start() cannot bind.
	blocker, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test helper
	require.NoError(t, err)
	port := blocker.Addr().(*net.TCPAddr).Port
	defer func() { _ = blocker.Close() }()

	enricher, err := pipeline.NewEnricher(output.EnricherConfig{
		TruncateEventThreshold: 4096,
		TruncateFieldThreshold: 512,
	})
	require.NoError(t, err)
	dispatcher := pipeline.NewDispatcher(nil)
	pipe, err := pipeline.NewPipeline(enricher, dispatcher, nil)
	require.NoError(t, err)

	cat, err := catalog.New([]output.Type{
		{
			Name:   "noop",
			Schema: output.Schema{},
			New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
				return &testutil.MockDriver{DriverName: "noop"}, nil
			},
		},
	})
	require.NoError(t, err)

	srv, err := api.NewServer(&api.ServerConfig{
		Pipeline: pipe,
		Catalog:  cat,
		Config: &core.Config{
			ListenAddress: "127.0.0.1",
			ListenPort:    port,
		},
		Logger: slog.Default(),
	})
	require.NoError(t, err)

	a := &app{
		pipe: pipe,
		srv:  srv,
	}

	errCh := make(chan error, 1)
	a.serve(errCh)

	select {
	case receivedErr := <-errCh:
		require.Error(t, receivedErr, "serve() must send Start error to channel")
		assert.Contains(t, receivedErr.Error(), "bind")
	case <-time.After(5 * time.Second):
		t.Fatal("serve() did not propagate Start error to channel within 5s")
	}
}

func TestResolveUIAssetsDisabled(t *testing.T) {
	assets := resolveUIAssets(false, fstest.MapFS{"index.html": {Data: []byte("x")}})
	assert.Nil(t, assets, "ui.enabled=false must yield nil regardless of embedded assets")
}

func TestResolveUIAssetsEnabledNoEmbed(t *testing.T) {
	assets := resolveUIAssets(true, nil)
	assert.Nil(t, assets, "ui.enabled=true on a stub binary must yield nil (warning is logged)")
}

func TestResolveUIAssetsEnabledWithEmbed(t *testing.T) {
	dist := fstest.MapFS{"index.html": {Data: []byte("stub-index")}}
	assets := resolveUIAssets(true, dist)
	require.NotNil(t, assets)
	assert.Equal(t, dist, assets, "ui.enabled=true + embedded assets must pass through unchanged")
}

func TestRunUIEnabledBinaryRoutingMatchesTag(t *testing.T) {
	cfg, port, managementPort := writeServerConfig(t, "ui:\n  enabled: true\n  event_source: inmemory")
	outs := writeTestOutputs(t, "outputs:\n  inmemory:\n    capacity: 1000\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, []string{outs})
	}()

	waitForServer(t, port)
	waitForServer(t, managementPort)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", managementPort)) //nolint:noctx // test helper
	require.NoError(t, err)
	_ = resp.Body.Close()
	if ui.Enabled {
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"GET / on the management listener of a builtinui build with ui.enabled=true serves the embedded index")
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
	} else {
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "a stub build serves no UI")
	}

	ingestionRoot, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port)) //nolint:noctx // test helper
	require.NoError(t, err)
	_ = ingestionRoot.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, ingestionRoot.StatusCode, "the ingestion listener never serves the UI")

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not exit within 15 seconds")
	}
}

func TestRunUIDisabledDoesNotServeStaticAssets(t *testing.T) {
	cfg, _, managementPort := writeServerConfig(t, "")
	outs := writeTestOutputs(t, "outputs:\n  webhook:\n    host: http://127.0.0.1:19999\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, []string{outs})
	}()

	waitForServer(t, managementPort)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", managementPort)) //nolint:noctx // test helper
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "with ui.enabled=false the management listener serves no UI")

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not exit within 15 seconds")
	}
}

func TestCloseOutputsLogsOnCloseError(t *testing.T) {
	t.Helper()

	cfg := testutil.DefaultRuntimeConfig()
	cfg.QueueSize = 1
	failing := pipeline.NewOutput(&testutil.MockDriver{
		DriverName: "failing",
		CloseFunc:  func() error { return errors.New("close failed") },
	}, &cfg, nil)

	closeOutputs([]*pipeline.Output{failing})
}

// With a persistent database, an output file that writes a secret inline stops startup before the database opens.
func TestNewAppRefusesInlineSecretsInOutputFilesForAPersistentDatabase(t *testing.T) {
	cfg := loadDefaultConfigForCmdTest(t)
	cfg.Database.Backend = core.DatabaseSQLite
	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "token", Type: "string", Secret: true}}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)
	outs := &config.OutputsConfig{Outputs: map[string]map[string]any{"webhook": {"token": "private-value"}}}

	_, err = NewApp(t.Context(), cfg, outs, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), cat, slog.Default())
	require.ErrorContains(t, err, `output files: output "webhook": token: secrets cannot be stored; use token_file`)
	assert.NotContains(t, err.Error(), "private-value")
}

// With sqlite, an output created through the API and the layout survive a restart, the files hold
// no secret value, and the output files are provisioned again.
func TestNewAppWithSQLiteKeepsAPIOutputsAcrossRestartsWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(secret, []byte("private-token-value"), 0o600))
	cfg := loadDefaultConfigForCmdTest(t)
	cfg.Database.Backend = core.DatabaseSQLite
	cfg.Database.SQLite.Path = filepath.Join(dir, "sidekick.db")
	var built []string
	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "token", Type: "string", Secret: true}}},
		New: func(raw map[string]any, _ output.Deps) (output.Driver, error) {
			built = append(built, fmt.Sprint(raw["token"]))
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)
	collector := func() *metrics.Collector { return metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}) }
	files := &config.OutputsConfig{Outputs: map[string]map[string]any{}}

	first, err := NewApp(t.Context(), cfg, files, collector(), cat, slog.Default())
	require.NoError(t, err)
	workers, stop := context.WithCancel(context.Background())
	first.reloader.BindWorkerContext(workers, time.Second)
	first.pipe.Start(workers, stop)
	_, err = first.reloader.ApplyOutput(t.Context(), "webhook", 0, map[string]any{"token_file": secret})
	require.NoError(t, err)
	require.NoError(t, first.db.SavePipelineLayout(t.Context(), &core.PipelineLayout{Nodes: []core.LayoutNode{{ID: "webhook", X: 1}}}))
	first.shutdown()

	for _, name := range []string{cfg.Database.SQLite.Path, cfg.Database.SQLite.Path + "-wal"} {
		data, err := os.ReadFile(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoError(t, err)
		assert.NotContains(t, string(data), "private-token-value", name)
	}

	second, err := NewApp(t.Context(), cfg, files, collector(), cat, slog.Default())
	require.NoError(t, err)
	t.Cleanup(second.shutdown)
	assert.Equal(t, []string{"private-token-value", "private-token-value"}, built, "rebuilt from the secret file at restart")
	stored, err := second.db.GetOutputConfig(t.Context(), "webhook")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"token_file": secret}, stored.Config)
	layout, err := second.db.GetPipelineLayout(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []core.LayoutNode{{ID: "webhook", X: 1}}, layout.Nodes)
}

// An event source stored through the API that does not build leaves the events API unavailable; startup goes on.
func TestNewAppStartsWhenTheStoredEventSourceDoesNotBuild(t *testing.T) {
	dir := t.TempDir()
	cfg := loadDefaultConfigForCmdTest(t)
	cfg.Database.Backend = core.DatabaseSQLite
	cfg.Database.SQLite.Path = filepath.Join(dir, "sidekick.db")
	cfg.UI.Enabled = true
	cfg.UI.EventSource = "webhook"
	db, err := database.OpenSQLite(t.Context(), cfg.Database.SQLite.Path)
	require.NoError(t, err)
	_, err = db.SaveOutputConfig(t.Context(), "webhook", 0, map[string]any{"token_file": filepath.Join(dir, "missing")})
	require.NoError(t, err)
	require.NoError(t, db.Close())
	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "token", Type: "string", Secret: true}}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)

	a, err := NewApp(t.Context(), cfg, &config.OutputsConfig{Outputs: map[string]map[string]any{}},
		metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), cat, slog.Default())
	require.NoError(t, err)
	t.Cleanup(a.shutdown)
	statuses := a.pipe.CollectOutputStatus()
	require.Len(t, statuses, 1)
	assert.Equal(t, pipeline.HealthFailed, statuses[0].Status)
}

// The postgres settings of the core file open the database; FALCOSIDEKICK_E2E_POSTGRES_DSN names the server.
func TestCreateDatabasePostgresFromTheCoreFile(t *testing.T) {
	dsn := postgresDSN(t)
	server, err := url.Parse(dsn)
	require.NoError(t, err)
	password, _ := server.User.Password()
	passwordFile := filepath.Join(t.TempDir(), "pg")
	require.NoError(t, os.WriteFile(passwordFile, []byte(password+"\n"), 0o600))
	cfg, err := config.Load(writeTestConfig(t, fmt.Sprintf(`
database:
  backend: postgres
  postgres:
    host: %s
    port: %s
    database: %s
    user: %s
    password_file: %s
    sslmode: disable
`, server.Hostname(), server.Port(), strings.TrimPrefix(server.Path, "/"), server.User.Username(), passwordFile)))
	require.NoError(t, err)
	require.Empty(t, cfg.Validate())

	db, err := createDatabase(t.Context(), &cfg.Database)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.GetOutputConfigs(t.Context())
	require.NoError(t, err)
}

// postgresTestDatabase creates an empty database on the test postgres and returns core settings for it.
func postgresTestDatabase(t *testing.T) *config.Config {
	t.Helper()
	dsn := postgresDSN(t)
	server, err := url.Parse(dsn)
	require.NoError(t, err)
	name := fmt.Sprintf("fsk_%d", time.Now().UnixNano())
	admin, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	_, err = admin.ExecContext(t.Context(), "CREATE DATABASE "+name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = admin.Close()
	})
	password, _ := server.User.Password()
	port, err := strconv.Atoi(server.Port())
	require.NoError(t, err)
	cfg := loadDefaultConfigForCmdTest(t)
	cfg.Database.Backend = core.DatabasePostgres
	cfg.Database.Postgres = core.PostgresConfig{
		Host: server.Hostname(), Port: port, Database: name, User: server.User.Username(), Password: password,
		SSLMode: core.PostgresSSLDisable, MaxConnections: 4, PollInterval: 200 * time.Millisecond,
	}
	require.Empty(t, cfg.Validate())
	return cfg
}

// Two instances on one postgres: a write on one reaches the other through the notification, and
// through the poll when the notification is lost.
func TestReplicasConvergeThroughNotificationsAndPolling(t *testing.T) {
	cfg := postgresTestDatabase(t)
	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "address", Type: "string"}}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)
	start := func(poll time.Duration) *app {
		c := *cfg
		c.Database.Postgres.PollInterval = poll
		a, err := NewApp(t.Context(), &c, &config.OutputsConfig{Outputs: map[string]map[string]any{}},
			metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), cat, slog.Default())
		require.NoError(t, err)
		appCtx, cancel := context.WithCancel(context.Background())
		workers, stopWorkers := context.WithCancel(context.Background())
		a.pipe.Start(workers, stopWorkers)
		a.reloader.BindWorkerContext(workers, time.Second)
		require.NoError(t, a.startReplicaSync(appCtx, &c.Database))
		t.Cleanup(func() {
			cancel()
			a.shutdown()
		})
		return a
	}
	running := func(a *app) []string { return a.pipe.Dispatcher().OutputNames() }
	settings, err := database.PostgresSettings(&cfg.Database.Postgres)
	require.NoError(t, err)
	admin := stdlib.OpenDB(*settings)
	t.Cleanup(func() { _ = admin.Close() })

	writer := start(time.Hour)
	reader := start(time.Hour)
	polled := start(300 * time.Millisecond)
	require.Eventually(t, func() bool {
		var listeners int
		err := admin.QueryRowContext(t.Context(),
			"SELECT count(*) FROM pg_stat_activity WHERE query LIKE 'LISTEN %' AND datname = current_database()").Scan(&listeners)
		return err == nil && listeners == 3
	}, 5*time.Second, 20*time.Millisecond, "every instance listens")

	_, err = writer.reloader.ApplyOutput(t.Context(), "webhook", 0, map[string]any{"address": "http://a"})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return slices.Equal(running(reader), []string{"webhook"}) }, 5*time.Second, 20*time.Millisecond,
		"the notification reaches an instance that polls only hourly")

	// A change that sends no notification: only the poll can see it.
	_, err = admin.ExecContext(t.Context(), "DELETE FROM falcosidekick_outputs WHERE name = 'webhook'")
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(running(polled)) == 0 }, 5*time.Second, 50*time.Millisecond, "the poll sees it")
	assert.Equal(t, []string{"webhook"}, running(reader), "an instance that polls hourly does not")
}

// postgresDSN returns the test postgres; without it the test is skipped, or fails when
// FALCOSIDEKICK_E2E_POSTGRES_REQUIRED is set, as in CI.
func postgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("FALCOSIDEKICK_E2E_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("FALCOSIDEKICK_E2E_POSTGRES_REQUIRED") != "" {
			t.Fatal("FALCOSIDEKICK_E2E_POSTGRES_DSN is not set")
		}
		t.Skip("FALCOSIDEKICK_E2E_POSTGRES_DSN is not set")
	}
	return dsn
}
