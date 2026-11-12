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
	"sync"
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
	"github.com/falcosecurity/falcosidekick/internal/outputs/inmemory"
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
	if !strings.Contains(extra, "shutdown_delay") {
		extra = "shutdown_delay: 0s\n" + extra
	}
	path = writeTestConfig(t, fmt.Sprintf(
		"listen_port: %d\nlisten_address: 127.0.0.1\nmanagement:\n  listen_port: %d\n%s", port, managementPort, extra))
	return path, port, managementPort
}

// On SIGTERM /readyz fails at once while events are still accepted for shutdown_delay, so
// Kubernetes stops routing to the pod before the listener closes; then the process stops.
func TestShutdownDrainsWhileNotReady(t *testing.T) {
	cfg, port, _ := writeServerConfig(t, "shutdown_delay: 1s\n")
	outs := writeTestOutputs(t, "outputs:\n  inmemory:\n    capacity: 10\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, []string{outs}) }()
	waitForServer(t, port)

	cancel()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + "/readyz") //nolint:noctx // test probe
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusServiceUnavailable
	}, 500*time.Millisecond, 10*time.Millisecond, "not ready right after SIGTERM")

	body := `{"rule":"r","priority":"Warning","output":"o","time":"2026-01-01T00:00:00Z","output_fields":{"a":"b"}}`
	resp, err := http.Post(base+"/", "application/json", strings.NewReader(body)) //nolint:noctx // test request
	require.NoError(t, err, "still accepting events while draining")
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after the shutdown delay")
	}
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

// waitForServer waits until the ingestion listener on port reports ready.
func waitForServer(t *testing.T, port int) {
	t.Helper()
	waitForOK(t, fmt.Sprintf("http://127.0.0.1:%d/readyz", port))
}

// waitForManagement waits until the management listener on port answers the API.
func waitForManagement(t *testing.T, port int) {
	t.Helper()
	waitForOK(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/version", port))
}

func waitForOK(t *testing.T, healthURL string) {
	t.Helper()
	const timeout = 5 * time.Second
	deadline := time.Now().Add(timeout)
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
	t.Fatalf("%s did not answer 200 within %s", healthURL, timeout)
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

// The integer 0 is "0s": refused with the range where a minimum applies, so startup fails before serving.
func TestRunReadsAZeroDurationAsTheAPIDoes(t *testing.T) {
	const webhookRuntime = "outputs:\n  webhook:\n    host: http://127.0.0.1:1\n    runtime:\n"
	for _, tt := range []struct {
		name, file, want string
	}{
		{name: "integer zero interval", file: webhookRuntime + "      retry:\n        initial_interval: 0\n",
			want: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "zero text interval", file: webhookRuntime + "      retry:\n        initial_interval: \"0s\"\n",
			want: "runtime.retry.initial_interval: must be a duration between 1ms and 1h"},
		{name: "integer zero reset timeout", file: webhookRuntime + "      circuit_breaker:\n        reset_timeout: 0\n",
			want: "runtime.circuit_breaker.reset_timeout: must be a duration between 1s and 1h"},
		{name: "integer zero ttl is no expiry", file: "outputs:\n  inmemory:\n    capacity: 10\n    ttl: 0\n"},
		{name: "zero text ttl is no expiry", file: "outputs:\n  inmemory:\n    capacity: 10\n    ttl: \"0s\"\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outputs := writeTestOutputs(t, tt.file)
			if tt.want != "" {
				err := run(context.Background(), "", []string{outputs})
				require.ErrorContains(t, err, tt.want)
				return
			}
			outs, err := config.LoadOutputs([]string{outputs})
			require.NoError(t, err)
			cat, err := catalog.New([]output.Type{inmemory.OutputType})
			require.NoError(t, err)
			built, err := createOutputs(context.Background(), loadDefaultConfigForCmdTest(t), outs.Outputs, cat,
				metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}))
			require.NoError(t, err)
			require.Len(t, built, 1)
			t.Cleanup(func() { _ = built[0].Close() })
			assert.Equal(t, "inmemory", built[0].Name())
		})
	}
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

func TestRunUIEventSourceThatCannotServeEvents(t *testing.T) {
	cfg := writeTestConfig(t, "ui:\n  enabled: true\n  event_source: webhook")
	outs := writeTestOutputs(t, "outputs:\n  webhook:\n    host: http://localhost:9999\n")
	err := run(context.Background(), cfg, []string{outs})
	require.ErrorContains(t, err, `ui.event_source: output type "webhook" cannot serve events to the UI; use one of: inmemory`)
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
	waitForManagement(t, managementPort)

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

	waitForManagement(t, managementPort)

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
	scan := func(when string, requireWAL bool) {
		t.Helper()
		for _, name := range []string{cfg.Database.SQLite.Path, cfg.Database.SQLite.Path + "-wal"} {
			data, err := os.ReadFile(name)
			if errors.Is(err, os.ErrNotExist) && !requireWAL {
				continue
			}
			require.NoError(t, err, "%s %s", when, name)
			assert.NotContains(t, string(data), "private-token-value", "%s %s", when, name)
		}
	}
	scan("while open", true)
	first.shutdown()
	scan("after close", false)

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
	cfg.ListenPort = findFreePort(t)
	cfg.Management.ListenPort = findFreePort(t)
	db, err := database.OpenSQLite(t.Context(), cfg.Database.SQLite.Path)
	require.NoError(t, err)
	_, err = db.SaveOutputConfig(t.Context(), "webhook", 0, map[string]any{"token_file": filepath.Join(dir, "missing")})
	require.NoError(t, err)
	require.NoError(t, db.Close())
	cat, err := catalog.New([]output.Type{{
		Name:        "webhook",
		EventSource: true,
		Schema:      output.Schema{Fields: []output.SchemaField{{Name: "token", Type: "string", Secret: true}}},
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

	serveErr := make(chan error, 1)
	a.serve(serveErr)
	waitForManagement(t, cfg.Management.ListenPort)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d/api/v1/events/search", cfg.Management.ListenPort), http.NoBody)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "the events API waits for its source")
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

// An unreachable postgres stops startup once connect_timeout has passed.
func TestCreateDatabaseGivesUpAfterTheConnectTimeout(t *testing.T) {
	cfg := loadDefaultConfigForCmdTest(t)
	cfg.Database = core.DatabaseConfig{Backend: core.DatabasePostgres, ConnectTimeout: 300 * time.Millisecond, Postgres: core.PostgresConfig{
		Host: "10.255.255.1", Port: 5432, Database: "falcosidekick", User: "falcosidekick",
		SSLMode: core.PostgresSSLDisable, MaxConnections: 1, PollInterval: time.Second,
	}}
	require.Empty(t, cfg.Validate())

	start := time.Now()
	_, err := createDatabase(t.Context(), &cfg.Database)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

// With postgres, API outputs and the layout survive a restart and no table holds a secret value.
func TestNewAppWithPostgresKeepsAPIOutputsAcrossRestartsWithoutSecrets(t *testing.T) {
	cfg := postgresTestDatabase(t)
	secret := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(secret, []byte("private-token-value"), 0o600))
	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "token", Type: "string", Secret: true}}},
		New: func(_ map[string]any, _ output.Deps) (output.Driver, error) {
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)
	files := &config.OutputsConfig{Outputs: map[string]map[string]any{}}
	open := func() *app {
		a, err := NewApp(t.Context(), cfg, files, metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), cat, slog.Default())
		require.NoError(t, err)
		return a
	}

	first := open()
	workers, stop := context.WithCancel(context.Background())
	first.pipe.Start(workers, stop)
	first.reloader.BindWorkerContext(workers, time.Second)
	_, err = first.reloader.ApplyOutput(t.Context(), "webhook", 0, map[string]any{"token_file": secret})
	require.NoError(t, err)
	require.NoError(t, first.db.SavePipelineLayout(t.Context(), &core.PipelineLayout{Nodes: []core.LayoutNode{{ID: "webhook"}}}))
	first.shutdown()

	settings, err := database.PostgresSettings(&cfg.Database.Postgres)
	require.NoError(t, err)
	admin := stdlib.OpenDB(*settings)
	t.Cleanup(func() { _ = admin.Close() })
	var dump string
	require.NoError(t, admin.QueryRowContext(t.Context(),
		"SELECT (SELECT string_agg(config::text, ' ') FROM falcosidekick_outputs) || "+
			"(SELECT string_agg(data::text, ' ') FROM falcosidekick_layout)").Scan(&dump))
	assert.Contains(t, dump, secret, "the reference is stored")
	assert.NotContains(t, dump, "private-token-value")

	second := open()
	t.Cleanup(second.shutdown)
	assert.Equal(t, []string{"webhook"}, second.pipe.Dispatcher().OutputNames())
	layout, err := second.db.GetPipelineLayout(t.Context())
	require.NoError(t, err)
	assert.Equal(t, []core.LayoutNode{{ID: "webhook"}}, layout.Nodes)
}

// replicaInstance is one Sidekick on the shared test postgres, recording the configs it builds.
type replicaInstance struct {
	*app
	builds []string
	mu     sync.Mutex
}

func (r *replicaInstance) built() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.builds)
}

func (r *replicaInstance) status(name string) pipeline.OutputStatus {
	statuses := r.pipe.CollectOutputStatus()
	for i := range statuses {
		if statuses[i].Name == name {
			return statuses[i]
		}
	}
	return pipeline.OutputStatus{}
}

// startReplica starts an instance that polls every poll; refuse makes its webhook builds of that address fail.
func startReplica(t *testing.T, cfg *config.Config, poll time.Duration, refuse string) *replicaInstance {
	t.Helper()
	r := &replicaInstance{}
	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "address", Type: "string"}}},
		New: func(raw map[string]any, _ output.Deps) (output.Driver, error) {
			address := fmt.Sprint(raw["address"])
			if address == refuse {
				return nil, errors.New("refused here")
			}
			r.mu.Lock()
			r.builds = append(r.builds, address)
			r.mu.Unlock()
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)
	c := *cfg
	c.Database.Postgres.PollInterval = poll
	a, err := NewApp(t.Context(), &c, &config.OutputsConfig{Outputs: map[string]map[string]any{}},
		metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), cat, slog.Default())
	require.NoError(t, err)
	r.app = a
	appCtx, cancel := context.WithCancel(context.Background())
	workers, stopWorkers := context.WithCancel(context.Background())
	a.pipe.Start(workers, stopWorkers)
	a.reloader.BindWorkerContext(workers, time.Second)
	require.NoError(t, a.startReplicaSync(appCtx, &c.Database))
	t.Cleanup(func() {
		cancel()
		a.shutdown()
	})
	return r
}

// Writes on one instance reach the others, by notification or, when none is sent, by the poll; a
// stale write is refused; a change one instance cannot build keeps its previous output until it can.
func TestReplicasApplyEveryKindOfChange(t *testing.T) {
	cfg := postgresTestDatabase(t)
	settings, err := database.PostgresSettings(&cfg.Database.Postgres)
	require.NoError(t, err)
	admin := stdlib.OpenDB(*settings)
	t.Cleanup(func() { _ = admin.Close() })

	writer := startReplica(t, cfg, time.Hour, "")
	notified := startReplica(t, cfg, time.Hour, "http://bad")
	polled := startReplica(t, cfg, 300*time.Millisecond, "")
	require.Eventually(t, func() bool {
		var listeners int
		err := admin.QueryRowContext(t.Context(),
			"SELECT count(*) FROM pg_stat_activity WHERE query LIKE 'LISTEN %' AND datname = current_database()").Scan(&listeners)
		return err == nil && listeners == 3
	}, 5*time.Second, 20*time.Millisecond)
	last := func(r *replicaInstance) string {
		b := r.built()
		if len(b) == 0 {
			return ""
		}
		return b[len(b)-1]
	}
	waitFor := func(r *replicaInstance, address, why string) {
		t.Helper()
		require.Eventually(t, func() bool { return last(r) == address }, 5*time.Second, 20*time.Millisecond, why)
	}

	v1, err := writer.reloader.ApplyOutput(t.Context(), "webhook", 0, map[string]any{"address": "http://one"})
	require.NoError(t, err)
	waitFor(notified, "http://one", "create by notification")
	v2, err := writer.reloader.ApplyOutput(t.Context(), "webhook", v1, map[string]any{"address": "http://two"})
	require.NoError(t, err)
	waitFor(notified, "http://two", "update by notification")
	waitFor(polled, "http://two", "update reaches the polling instance too")

	_, err = notified.reloader.ApplyOutput(t.Context(), "webhook", v1, map[string]any{"address": "http://stale"})
	require.ErrorIs(t, err, core.ErrVersionConflict, "a write based on a version another instance replaced")

	_, err = writer.reloader.ApplyOutput(t.Context(), "webhook", v2, map[string]any{"address": "http://bad"})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return notified.status("webhook").Status == pipeline.HealthDegraded }, 5*time.Second, 20*time.Millisecond,
		"a change this instance cannot build keeps the previous output")
	assert.Equal(t, "http://two", last(notified))
	entry, err := writer.db.GetOutputConfig(t.Context(), "webhook")
	require.NoError(t, err)
	_, err = writer.reloader.ApplyOutput(t.Context(), "webhook", entry.Version, map[string]any{"address": "http://three"})
	require.NoError(t, err)
	waitFor(notified, "http://three", "the next change applies")
	assert.Empty(t, notified.status("webhook").LastWarning)

	// Changes that send no notification: only the poll sees them.
	_, err = admin.ExecContext(t.Context(),
		"UPDATE falcosidekick_outputs SET config = '{\"address\":\"http://silent\"}', version = nextval('falcosidekick_version') WHERE name = 'webhook'")
	require.NoError(t, err)
	_, err = admin.ExecContext(t.Context(),
		"INSERT INTO falcosidekick_outputs (name, config, version, provisioned, updated_at) "+
			"VALUES ('webhook2', '{}', nextval('falcosidekick_version'), false, 0)")
	require.NoError(t, err)
	waitFor(polled, "http://silent", "a silent update is polled")
	// webhook2 is no output type, so the instance that sees it reports it failed.
	require.Eventually(t, func() bool { return polled.status("webhook2").Status == pipeline.HealthFailed }, 5*time.Second, 20*time.Millisecond,
		"a silent create is polled")
	assert.Equal(t, "http://three", last(notified), "an instance polling hourly misses them")
	assert.Empty(t, notified.status("webhook2").Status)
}

// Without output files, SIGHUP and a change in api.secret_dirs still reread the secret files of API
// outputs and rebuild those that changed.
func TestRotatedSecretOfAnAPIOutputWithoutOutputFiles(t *testing.T) {
	tests := []struct {
		name    string
		sighup  bool
		inRoots bool
	}{
		{name: "SIGHUP", sighup: true},
		{name: "secret directory watcher", inRoots: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testRotatedAPISecret(t, tt.sighup, tt.inRoots)
		})
	}
}

func testRotatedAPISecret(t *testing.T, sighup, inRoots bool) {
	root := t.TempDir()
	secret := filepath.Join(root, "webhook", "token")
	require.NoError(t, os.Mkdir(filepath.Dir(secret), 0o700))
	require.NoError(t, os.WriteFile(secret, []byte("first"), 0o600))
	var (
		mu    sync.Mutex
		built []string
	)
	cat, err := catalog.New([]output.Type{{
		Name:   "webhook",
		Schema: output.Schema{Fields: []output.SchemaField{{Name: "token", Type: "string", Secret: true}}},
		New: func(raw map[string]any, _ output.Deps) (output.Driver, error) {
			mu.Lock()
			built = append(built, fmt.Sprint(raw["token"]))
			mu.Unlock()
			return &testutil.MockDriver{DriverName: "webhook"}, nil
		},
	}})
	require.NoError(t, err)
	cfg := loadDefaultConfigForCmdTest(t)
	a, err := NewApp(t.Context(), cfg, &config.OutputsConfig{Outputs: map[string]map[string]any{}},
		metrics.NewCollector(core.MetricsConfig{MaxLabelValues: 1000}), cat, slog.Default())
	require.NoError(t, err)
	appCtx, cancel := context.WithCancel(context.Background())
	workers, stopWorkers := context.WithCancel(context.Background())
	a.pipe.Start(workers, stopWorkers)
	var secretDirs []string
	if inRoots {
		secretDirs = []string{root}
	}
	// No poller: the change must reach the output through the watcher or the signal alone.
	reloadCfg := cfg.Reload
	reloadCfg.PollInterval = 0
	a.startReloadWatchers(appCtx, workers, nil, secretDirs, reloadCfg)
	t.Cleanup(func() {
		cancel()
		a.shutdown()
	})
	_, err = a.reloader.ApplyOutput(t.Context(), "webhook", 0, map[string]any{"token_file": secret})
	require.NoError(t, err)

	// Rotations replace the file whole, as the kubelet does: a reload never reads it half written.
	rotate := func() error {
		tmp := secret + ".tmp"
		if err := os.WriteFile(tmp, []byte("rotated"), 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, secret)
	}
	require.NoError(t, rotate())
	if sighup {
		require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGHUP))
	}
	require.Eventually(t, func() bool {
		// The watcher starts in the background and misses a rotation before it watches the mount.
		if !sighup && rotate() != nil {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		return slices.Equal(built, []string{"first", "rotated"})
	}, 5*time.Second, 20*time.Millisecond)
}
