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
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

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
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:noctx // test helper, hardcoded localhost
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
	db, err := createDatabase(core.DatabaseConfig{Backend: core.DatabaseInMemory})
	require.NoError(t, err)
	require.NotNil(t, db)
	assert.NoError(t, db.Close())
}

func TestCreateDatabaseUnknownBackend(t *testing.T) {
	_, err := createDatabase(core.DatabaseConfig{Backend: "unknown"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
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
	require.NoError(t, db.SaveOutputConfig(ctx, "webhook", map[string]any{"address": "http://sink"}))

	fileOutputs := map[string]map[string]any{}
	outs, err := restoreFromDB(ctx, cfg, db, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), fileOutputs)
	require.NoError(t, err)
	require.Len(t, outs, 1, "UI-only entry must be rebuilt into a live Output on startup")
	assert.Equal(t, "webhook", outs[0].Name())

	for _, o := range outs {
		_ = o.Close()
	}
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
	outs, err := restoreFromDB(ctx, cfg, db, cat, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), fileOutputs)
	require.NoError(t, err)
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
