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

package reload

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/database"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

// caRecorder records the CA file contents each output was built with, in build order, read at build
// as a TLS driver does.
type caRecorder struct {
	cas map[string][]string
	mu  sync.Mutex
}

func (c *caRecorder) outputType(name string) output.Type {
	return output.Type{
		Name: name,
		Schema: output.Schema{Fields: []output.SchemaField{
			{Name: "token", Type: "string", Secret: true},
			{Name: "tls.ca_file", Type: "string", File: true},
		}},
		New: func(raw map[string]any, _ output.Deps) (output.Driver, error) {
			tls, _ := raw["tls"].(map[string]any)
			path, _ := tls["ca_file"].(string)
			var ca string
			if path != "" {
				data, err := os.ReadFile(path)
				if err != nil {
					return nil, err
				}
				ca = string(data)
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.cas == nil {
				c.cas = make(map[string][]string)
			}
			c.cas[name] = append(c.cas[name], ca)
			return &testutil.MockDriver{DriverName: name}, nil
		},
	}
}

func (c *caRecorder) builds(name string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.cas[name])
}

// A renewed CA file rebuilds the file output that reads it, an unchanged one is a no-op, and an
// unreadable one fails the reload like an unreadable secret file.
func TestReloadRebuildsTheFileOutputWhoseFileFieldChanged(t *testing.T) {
	tests := []struct {
		change      func(t *testing.T, ca string)
		name        string
		wantErr     string
		wantWebhook []string
		wantNoops   float64
		wantFailed  float64
	}{
		{
			name:        "renewed",
			change:      func(t *testing.T, ca string) { writeFile(t, ca, "renewed") },
			wantWebhook: []string{"first", "renewed"},
		},
		{
			name:        "unchanged",
			change:      func(_ *testing.T, _ string) {},
			wantWebhook: []string{"first"},
			wantNoops:   1,
		},
		{
			name:        "rewritten with the same contents",
			change:      func(t *testing.T, ca string) { writeFile(t, ca, "first") },
			wantWebhook: []string{"first"},
			wantNoops:   1,
		},
		{
			name:        "unreadable",
			change:      func(t *testing.T, ca string) { require.NoError(t, os.Remove(ca)) },
			wantErr:     `reload files: output "webhook": tls.ca_file: file does not exist`,
			wantWebhook: []string{"first"},
			wantFailed:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			ca := filepath.Join(dir, "webhook-ca.pem")
			writeFile(t, ca, "first")
			otherCA := filepath.Join(dir, "other-ca.pem")
			writeFile(t, otherCA, "other")
			path := filepath.Join(t.TempDir(), "outputs.yaml")
			writeOutputsYAML(t, path, fmt.Sprintf("outputs:\n  webhook:\n    tls:\n      ca_file: %s\n  other:\n    tls:\n      ca_file: %s\n", ca, otherCA))

			rec := &caRecorder{}
			cat, err := catalog.New([]output.Type{rec.outputType("webhook"), rec.outputType("other")})
			require.NoError(t, err)
			env := newReloaderTestEnv(t, nil)
			defer env.shutdown(t)
			reg := prometheus.NewRegistry()
			r := NewReloader(&ReloaderConfig{
				OutputPaths: []string{path}, Catalog: cat, Dispatcher: env.d, Registry: reg,
				RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
			})
			ctx := t.Context()
			require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))

			tt.change(t, ca)
			err = r.Reload(ctx, env.workerRunCtx, time.Second)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				assert.NotContains(t, err.Error(), dir)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantWebhook, rec.builds("webhook"))
			assert.Equal(t, []string{"other"}, rec.builds("other"), "the other output is not rebuilt")
			assert.ElementsMatch(t, []string{"other", "webhook"}, env.d.OutputNames())

			gathered, err := reg.Gather()
			require.NoError(t, err)
			assert.Equal(t, 2.0, getMetricValueBySource(gathered, metricReloadTotal, SourceFile))
			assert.Equal(t, tt.wantFailed, getMetricValueBySource(gathered, metricReloadFailures, SourceFile))
			timed := getMetricBySource(gathered, "falcosidekick_reload_duration_seconds", SourceFile).GetHistogram().GetSampleCount()
			assert.Equal(t, tt.wantNoops, 2-float64(timed), "a no-op records no duration")
		})
	}
}

// The file outputs running at startup are the base: an unchanged CA file rebuilds nothing at the
// first reload, a renewed one rebuilds the output once.
func TestReloadComparesWithTheFilesReadAtStartup(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	writeFile(t, ca, "first")
	path := filepath.Join(t.TempDir(), "outputs.yaml")
	writeOutputsYAML(t, path, fmt.Sprintf("outputs:\n  webhook:\n    tls:\n      ca_file: %s\n", ca))
	rec := &caRecorder{}
	cat, err := catalog.New([]output.Type{rec.outputType("webhook")})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	running := map[string]map[string]any{"webhook": {"tls": map[string]any{"ca_file": ca}}}
	r := NewReloader(&ReloaderConfig{
		OutputPaths: []string{path}, Catalog: cat, Dispatcher: env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
		InitialOutputs: running, FileOutputs: running,
	})
	ctx := t.Context()

	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
	assert.Empty(t, rec.builds("webhook"), "the startup build is not repeated")

	writeFile(t, ca, "renewed")
	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
	assert.Equal(t, []string{"renewed"}, rec.builds("webhook"))
}

// A reload rereads the File field files of API outputs: a renewed one rebuilds the output and leaves
// the stored config and version alone; an unreadable one keeps the running output.
func TestReloaderRebuildsAPIOutputsWhoseFileFieldChanged(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	writeFile(t, ca, "first")
	rec := &caRecorder{}
	cat, err := catalog.New([]output.Type{rec.outputType("webhook")})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	db := database.NewMemory()
	r := NewReloader(&ReloaderConfig{
		Catalog: cat, Dispatcher: env.d, Database: db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)
	ctx := t.Context()
	cfg := map[string]any{"tls": map[string]any{"ca_file": ca}}
	version, err := r.ApplyOutput(ctx, "webhook", 0, cfg)
	require.NoError(t, err)

	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
	assert.Equal(t, []string{"first"}, rec.builds("webhook"), "an unchanged file rebuilds nothing")

	writeFile(t, ca, "renewed")
	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
	assert.Equal(t, []string{"first", "renewed"}, rec.builds("webhook"), "rebuilt once")

	require.NoError(t, os.Remove(ca))
	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second), "an unreadable file keeps the running output")
	assert.Equal(t, []string{"first", "renewed"}, rec.builds("webhook"))
	assert.Equal(t, []string{"webhook"}, env.d.OutputNames())

	stored, err := db.GetOutputConfig(ctx, "webhook")
	require.NoError(t, err)
	assert.Equal(t, version, stored.Version)
	assert.Equal(t, cfg, stored.Config)
}

// An output applied through the API with an unreadable File field file is refused before it is built
// or stored.
func TestApplyOutputRefusesAnUnreadableFileField(t *testing.T) {
	dir := t.TempDir()
	rec := &caRecorder{}
	cat, err := catalog.New([]output.Type{rec.outputType("webhook")})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	db := database.NewMemory()
	r := NewReloader(&ReloaderConfig{
		Catalog: cat, Dispatcher: env.d, Database: db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)

	_, err = r.ApplyOutput(t.Context(), "webhook", 0, map[string]any{"tls": map[string]any{"ca_file": filepath.Join(dir, "missing")}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `output "webhook": tls.ca_file: file does not exist`)
	assert.NotContains(t, err.Error(), dir)
	assert.Empty(t, rec.builds("webhook"))
	stored, err := db.GetOutputConfig(t.Context(), "webhook")
	require.NoError(t, err)
	assert.Nil(t, stored)
}

// Reconcile records the files it built with: a later renewal rebuilds the output once, not at every
// reload or reconcile.
func TestReconcileThenRenewedFileFieldRebuildsOnce(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	writeFile(t, ca, "first")
	rec := &caRecorder{}
	cat, err := catalog.New([]output.Type{rec.outputType("webhook")})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	db := database.NewMemory()
	r := NewReloader(&ReloaderConfig{
		Catalog: cat, Dispatcher: env.d, Database: db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)
	ctx := t.Context()
	_, err = db.SaveOutputConfig(ctx, "webhook", 0, map[string]any{"tls": map[string]any{"ca_file": ca}})
	require.NoError(t, err)

	require.NoError(t, r.Reconcile(ctx))
	require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
	assert.Equal(t, []string{"first"}, rec.builds("webhook"))

	writeFile(t, ca, "renewed")
	for range 2 {
		require.NoError(t, r.Reload(ctx, env.workerRunCtx, time.Second))
		require.NoError(t, r.Reconcile(ctx))
	}
	assert.Equal(t, []string{"first", "renewed"}, rec.builds("webhook"))
}

// A reconciled change whose File field file cannot be read here is not applied; the previous output
// keeps running and the change is applied once the file is readable.
func TestReconcileReportsAnUnreadableFileField(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	rec := &caRecorder{}
	cat, err := catalog.New([]output.Type{rec.outputType("webhook")})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)
	db := database.NewMemory()
	r := NewReloader(&ReloaderConfig{
		Catalog: cat, Dispatcher: env.d, Database: db,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
	})
	r.BindWorkerContext(env.workerRunCtx, time.Second)
	ctx := t.Context()
	_, err = db.SaveOutputConfig(ctx, "webhook", 0, map[string]any{"tls": map[string]any{"ca_file": ca}})
	require.NoError(t, err)

	require.NoError(t, r.Reconcile(ctx))
	assert.Empty(t, rec.builds("webhook"))
	assert.Empty(t, env.d.OutputNames())

	writeFile(t, ca, "first")
	require.NoError(t, r.Reconcile(ctx))
	assert.Equal(t, []string{"first"}, rec.builds("webhook"))
	assert.Equal(t, []string{"webhook"}, env.d.OutputNames())
}

// A CA certificate mounted by the kubelet is renewed: the output that reads it is rebuilt with the
// new certificate without SIGHUP, and the other output keeps running as it was.
func TestRenewedCAFileRebuildsOnlyItsOutputWithoutSIGHUP(t *testing.T) {
	tests := []struct {
		name    string
		inRoots bool
		api     bool
	}{
		{name: "file output, mount under api.secret_dirs", inRoots: true},
		{name: "file output, mount outside api.secret_dirs"},
		{name: "API output, mount under api.secret_dirs", inRoots: true, api: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			mount := filepath.Join(root, "webhook")
			kubeletMount(t, mount, "..2026_11_08_v1", map[string]string{"ca.crt": "first"})
			caPath := filepath.Join(mount, "ca.crt")
			webhookCfg := map[string]any{"tls": map[string]any{"ca_file": caPath}}
			path := filepath.Join(t.TempDir(), "outputs.yaml")
			if tt.api {
				writeOutputsYAML(t, path, "outputs:\n  other: {}\n")
			} else {
				writeOutputsYAML(t, path, fmt.Sprintf("outputs:\n  webhook:\n    tls:\n      ca_file: %s\n  other: {}\n", caPath))
			}

			rec := &caRecorder{}
			cat, err := catalog.New([]output.Type{rec.outputType("webhook"), rec.outputType("other")})
			require.NoError(t, err)
			env := newReloaderTestEnv(t, nil)
			defer env.shutdown(t)
			r := NewReloader(&ReloaderConfig{
				OutputPaths: []string{path}, Catalog: cat, Dispatcher: env.d, Database: database.NewMemory(),
				RuntimeDefaults: testutil.DefaultRuntimeConfig(), Deps: output.Deps{Logger: slog.Default()}, Logger: slog.Default(),
			})
			r.BindWorkerContext(env.workerRunCtx, 10*time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			require.NoError(t, r.Reload(ctx, env.workerRunCtx, 10*time.Second))
			if tt.api {
				_, err := r.ApplyOutput(ctx, "webhook", 0, webhookCfg)
				require.NoError(t, err)
			}
			require.Equal(t, []string{"first"}, rec.builds("webhook"))

			var roots []string
			if tt.inRoots {
				roots = []string{root}
			}
			var w *Watcher
			reloadFn := func() error {
				err := r.Reload(ctx, env.workerRunCtx, 10*time.Second)
				w.Refresh()
				return err
			}
			w = NewWatcher([]string{path}, NewSecretPaths(roots, r.FilePaths).Dirs, testDebounce, reloadFn, slog.Default())
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = w.Run(ctx)
			}()
			defer func() {
				cancel()
				<-done
			}()
			<-w.Ready()

			kubeletMount(t, mount, "..2026_11_08_v2", map[string]string{"ca.crt": "renewed"})
			require.Eventually(t, func() bool { return slices.Equal(rec.builds("webhook"), []string{"first", "renewed"}) },
				5*time.Second, 10*time.Millisecond, "the output is rebuilt with the renewed certificate")
			time.Sleep(3 * testDebounce)
			assert.Equal(t, []string{"first", "renewed"}, rec.builds("webhook"))
			assert.Equal(t, []string{""}, rec.builds("other"), "the other output is not rebuilt")
		})
	}
}
