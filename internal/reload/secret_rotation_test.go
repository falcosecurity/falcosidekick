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
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/testutil"
)

// buildRecorder records the token each output was built with, in build order.
type buildRecorder struct {
	tokens map[string][]string
	mu     sync.Mutex
}

func (b *buildRecorder) outputType(name string) output.Type {
	return output.Type{
		Name: name,
		Schema: output.Schema{Fields: []output.SchemaField{
			{Name: "token", Type: "string", Secret: true},
			{Name: "tls.ca_file", Type: "string", File: true},
		}},
		New: func(raw map[string]any, _ output.Deps) (output.Driver, error) {
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.tokens == nil {
				b.tokens = make(map[string][]string)
			}
			b.tokens[name] = append(b.tokens[name], fmt.Sprint(raw["token"]))
			return &testutil.MockDriver{DriverName: name}, nil
		},
	}
}

func (b *buildRecorder) builds(name string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.tokens[name])
}

func newFileReloader(t *testing.T, env *reloaderTestEnv, cat *catalog.Catalog, path string, fileOutputs map[string]map[string]any) *Reloader {
	t.Helper()
	return NewReloader(&ReloaderConfig{
		OutputPaths:     []string{path},
		Catalog:         cat,
		Dispatcher:      env.d,
		RuntimeDefaults: testutil.DefaultRuntimeConfig(),
		Deps:            output.Deps{Logger: slog.Default()},
		Logger:          slog.Default(),
		InitialOutputs:  map[string]map[string]any{},
		FileOutputs:     fileOutputs,
	})
}

func TestReloaderFilePathsFollowTheOutputFiles(t *testing.T) {
	secrets := t.TempDir()
	token := filepath.Join(secrets, "token")
	writeFile(t, token, "t")
	ca := filepath.Join(secrets, "ca.pem")
	path := filepath.Join(t.TempDir(), "outputs.yaml")
	rec := &buildRecorder{}
	cat, err := catalog.New([]output.Type{rec.outputType("webhook"), rec.outputType("other")})
	require.NoError(t, err)
	env := newReloaderTestEnv(t, nil)
	defer env.shutdown(t)

	r := newFileReloader(t, env, cat, path, map[string]map[string]any{
		"webhook": {"token_file": "/startup/token"},
		"unknown": {"token_file": "/never/listed"},
	})
	assert.Equal(t, []string{"/startup/token"}, r.FilePaths(), "the outputs given at startup, of known types")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	writeOutputsYAML(t, path, fmt.Sprintf("outputs:\n  webhook:\n    token_file: %s\n    tls:\n      ca_file: %s\n  other:\n    token_file: %s\n", token, ca, token))
	require.NoError(t, r.Reload(ctx, env.workerRunCtx, 10*time.Second))
	assert.Equal(t, []string{ca, token}, r.FilePaths())

	writeOutputsYAML(t, path, "outputs:\n  webhook:\n    token: inline\n")
	require.NoError(t, r.Reload(ctx, env.workerRunCtx, 10*time.Second))
	assert.Empty(t, r.FilePaths())
}

// A Secret mounted by the kubelet is rotated: the output that reads it is rebuilt with the new
// value without SIGHUP, and the other output keeps running as it was.
func TestRotatedSecretFileRebuildsOnlyItsOutputWithoutSIGHUP(t *testing.T) {
	tests := []struct {
		name    string
		inRoots bool
	}{
		{name: "mount under api.secret_dirs", inRoots: true},
		{name: "file output path outside api.secret_dirs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			mount := filepath.Join(root, "webhook")
			kubeletMount(t, mount, "..2026_11_08_v1", map[string]string{"token": "first"})
			path := filepath.Join(t.TempDir(), "outputs.yaml")
			writeOutputsYAML(t, path, fmt.Sprintf("outputs:\n  webhook:\n    token_file: %s\n  other: {}\n", filepath.Join(mount, "token")))

			rec := &buildRecorder{}
			cat, err := catalog.New([]output.Type{rec.outputType("webhook"), rec.outputType("other")})
			require.NoError(t, err)
			env := newReloaderTestEnv(t, nil)
			defer env.shutdown(t)
			r := newFileReloader(t, env, cat, path, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			require.NoError(t, r.Reload(ctx, env.workerRunCtx, 10*time.Second))
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

			kubeletMount(t, mount, "..2026_11_08_v2", map[string]string{"token": "rotated"})
			require.Eventually(t, func() bool { return slices.Equal(rec.builds("webhook"), []string{"first", "rotated"}) },
				5*time.Second, 10*time.Millisecond, "the output is rebuilt with the rotated secret")
			time.Sleep(3 * testDebounce)
			assert.Equal(t, []string{"first", "rotated"}, rec.builds("webhook"))
			assert.Equal(t, []string{"<nil>"}, rec.builds("other"), "the other output is not rebuilt")
		})
	}
}
