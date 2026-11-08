// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
package hacktesting

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const stubKubectl = `#!/usr/bin/env bash
printf 'kubectl %s\n' "$*" >> "$STUB_LOG"
case "$*" in
  *" get -f "*component.yaml*) printf '%s' "$STUB_FOREIGN" ;;
  *" get pod "*) echo falcosidekick-0 ;;
  *" port-forward "*) echo "$$" >> "$STUB_PF"; exec /bin/sleep 30 ;;
esac
exit 0
`

const stubKind = `#!/usr/bin/env bash
printf 'kind %s\n' "$*" >> "$STUB_LOG"
if [[ "$1" == get ]]; then printf '%b' "$STUB_CLUSTERS"; fi
exit 0
`

const stubBun = `#!/usr/bin/env bash
printf 'bun %s\n' "$*" >> "$STUB_LOG"
if [[ -n "${STUB_BUN_HANG:-}" ]]; then
  echo "$$" > "$STUB_BUN_HANG"
  exec /bin/sleep 30
fi
exit "${STUB_BUN_EXIT:-0}"
`

const stubCurl = `#!/usr/bin/env bash
case "$*" in
  *%{http_code}*) printf '%s' "${STUB_HTTP_CODE:-200}" ;;
  *) printf '{}' ;;
esac
`

const stubPass = "#!/usr/bin/env bash\nexit 0\n"

type helperRun struct {
	stubLog string
	stubPF  string
	env     []string
}

func newHelperRun(t *testing.T, clusters string) *helperRun {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"kubectl": stubKubectl, "kind": stubKind, "bun": stubBun, "curl": stubCurl,
		"docker": stubPass, "make": stubPass, "sleep": stubPass,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700))
	}
	run := &helperRun{stubLog: filepath.Join(dir, "calls.log"), stubPF: filepath.Join(dir, "pf.pids")}
	run.env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_LOG="+run.stubLog, "STUB_PF="+run.stubPF, "STUB_CLUSTERS="+clusters,
		"KUBECONFIG=/nonexistent", "V3_FALCO_WAIT=0", "V3_WEBHOOK_WAIT=0", "V3_UI_WRITE_WAIT=0",
	)
	return run
}

func (r *helperRun) command(ctx context.Context, script string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "bash", append([]string{script}, args...)...)
	cmd.Env = r.env
	return cmd
}

func (r *helperRun) start(t *testing.T, script string, args ...string) (output string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cmd := r.command(ctx, script, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out.String(), exitErr.ExitCode()
	}
	require.NoError(t, err, out.String())
	return out.String(), 0
}

func (r *helperRun) calls(t *testing.T, prefix string) []string {
	t.Helper()
	raw, err := os.ReadFile(r.stubLog)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)
	var calls []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(line, prefix) {
			calls = append(calls, line)
		}
	}
	return calls
}

func (r *helperRun) mutations(t *testing.T) []string {
	t.Helper()
	var found []string
	for _, call := range r.calls(t, "kubectl") {
		for _, verb := range []string{" apply ", " delete ", " rollout restart ", " run "} {
			if strings.Contains(call, verb) {
				found = append(found, call)
			}
		}
	}
	found = append(found, r.calls(t, "kind load")...)
	return found
}

var helperScripts = []struct {
	named func(cluster string) (args, env []string)
	name  string
	path  string
	args  []string
}{
	{
		name: "live-test", path: "live-test/run.sh",
		named: func(cluster string) (args, env []string) { return nil, []string{"V3_KIND_CLUSTER=" + cluster} },
	},
	{
		name: "ui-dev-cluster", path: "ui-dev-cluster.sh", args: []string{"--skip-build", "--clean"},
		named: func(cluster string) (args, env []string) { return []string{"-k", cluster}, nil },
	},
}

func TestHelpersPinEveryKubectlCallToTheKindCluster(t *testing.T) {
	for _, script := range helperScripts {
		t.Run(script.name, func(t *testing.T) {
			run := newHelperRun(t, `dev\n`)
			run.start(t, script.path, script.args...)
			calls := run.calls(t, "kubectl")
			require.NotEmpty(t, calls)
			for _, call := range calls {
				assert.True(t, strings.HasPrefix(call, "kubectl --context kind-dev "), call)
			}
			assert.NotEmpty(t, run.calls(t, "kubectl --context kind-dev apply"))
		})
	}
}

func TestHelpersStopWithoutOneSelectedCluster(t *testing.T) {
	for _, script := range helperScripts {
		for name, clusters := range map[string]string{"none": "", "several": `a\nb\n`} {
			t.Run(script.name+"/"+name, func(t *testing.T) {
				run := newHelperRun(t, clusters)
				_, code := run.start(t, script.path, script.args...)
				assert.NotZero(t, code)
				assert.Empty(t, run.calls(t, "kubectl"))
				assert.Empty(t, run.mutations(t))
			})
		}
		t.Run(script.name+"/unknown name", func(t *testing.T) {
			run := newHelperRun(t, `dev\n`)
			args, env := script.named("other")
			run.env = append(run.env, env...)
			_, code := run.start(t, script.path, append(args, script.args...)...)
			assert.NotZero(t, code)
			assert.Empty(t, run.calls(t, "kubectl"))
		})
		t.Run(script.name+"/explicit among several", func(t *testing.T) {
			run := newHelperRun(t, `a\nb\n`)
			args, env := script.named("b")
			run.env = append(run.env, env...)
			run.start(t, script.path, append(args, script.args...)...)
			assert.NotEmpty(t, run.calls(t, "kubectl --context kind-b apply"))
		})
	}
}

func TestHelpersRefuseResourcesTheyDoNotOwn(t *testing.T) {
	for _, script := range helperScripts {
		t.Run(script.name, func(t *testing.T) {
			run := newHelperRun(t, `dev\n`)
			run.env = append(run.env, "STUB_FOREIGN=ConfigMap falcosidekick-config <none>\n")
			output, code := run.start(t, script.path, script.args...)
			assert.NotZero(t, code)
			assert.Contains(t, output, "ConfigMap/falcosidekick-config")
			assert.Empty(t, run.mutations(t))
		})
	}
}

func TestHelpersAcceptTheirOwnResources(t *testing.T) {
	run := newHelperRun(t, `dev\n`)
	run.env = append(run.env, "STUB_FOREIGN=ConfigMap falcosidekick-config falcosidekick-dev\n")
	run.start(t, "ui-dev-cluster.sh", "--skip-build")
	assert.NotEmpty(t, run.calls(t, "kubectl --context kind-dev apply"))
}

func TestTeardownDeletesOnlyByLabelAfterApply(t *testing.T) {
	const wantDelete = "kubectl --context kind-dev -n falco delete " +
		"configmap,service,deployment,components.instance.falcosecurity.dev " +
		"-l app.kubernetes.io/part-of=falcosidekick-dev --ignore-not-found"

	t.Run("live-test", func(t *testing.T) {
		run := newHelperRun(t, `dev\n`)
		run.start(t, "live-test/run.sh")
		assert.Equal(t, []string{wantDelete}, run.calls(t, "kubectl --context kind-dev -n falco delete"))
	})
	t.Run("ui-dev-cluster with clean", func(t *testing.T) {
		run := newHelperRun(t, `dev\n`)
		run.start(t, "ui-dev-cluster.sh", "--skip-build", "--clean")
		assert.Equal(t, []string{wantDelete}, run.calls(t, "kubectl --context kind-dev -n falco delete"))
	})
	t.Run("ui-dev-cluster keeps resources by default", func(t *testing.T) {
		run := newHelperRun(t, `dev\n`)
		run.start(t, "ui-dev-cluster.sh", "--skip-build")
		assert.Empty(t, run.calls(t, "kubectl --context kind-dev -n falco delete"))
	})
	t.Run("skip-deploy never deletes", func(t *testing.T) {
		run := newHelperRun(t, `dev\n`)
		run.start(t, "ui-dev-cluster.sh", "--skip-build", "--skip-deploy", "--clean")
		assert.Empty(t, run.calls(t, "kubectl --context kind-dev -n falco delete"))
	})
}

func TestUIDevClusterExitStatusIsTheDevServers(t *testing.T) {
	for _, code := range []int{0, 7} {
		run := newHelperRun(t, `dev\n`)
		run.env = append(run.env, "STUB_BUN_EXIT="+map[int]string{0: "0", 7: "7"}[code])
		output, got := run.start(t, "ui-dev-cluster.sh", "--skip-build")
		assert.Equal(t, code, got, output)
		assertStopped(t, run)
	}
}

func assertStopped(t *testing.T, run *helperRun) {
	t.Helper()
	raw, err := os.ReadFile(run.stubPF)
	require.NoError(t, err)
	for pid := range strings.FieldsSeq(string(raw)) {
		assert.Eventually(t, func() bool {
			return exec.CommandContext(t.Context(), "kill", "-0", pid).Run() != nil
		}, 5*time.Second, 20*time.Millisecond, "port-forward %s still running", pid)
	}
}

func TestUIDevClusterSignalsStopChildrenAndCleanUp(t *testing.T) {
	for name, signal := range map[string]syscall.Signal{"interrupt": syscall.SIGINT, "terminate": syscall.SIGTERM} {
		t.Run(name, func(t *testing.T) {
			run := newHelperRun(t, `dev\n`)
			bunPID := filepath.Join(t.TempDir(), "bun.pid")
			run.env = append(run.env, "STUB_BUN_HANG="+bunPID)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := run.command(ctx, "ui-dev-cluster.sh", "--skip-build", "--clean")
			require.NoError(t, cmd.Start())
			require.Eventually(t, func() bool {
				raw, err := os.ReadFile(bunPID)
				return err == nil && len(raw) > 0
			}, 20*time.Second, 20*time.Millisecond)

			require.NoError(t, cmd.Process.Signal(signal))
			_ = cmd.Wait()

			raw, err := os.ReadFile(bunPID)
			require.NoError(t, err)
			pid := strings.TrimSpace(string(raw))
			assert.Eventually(t, func() bool {
				return exec.CommandContext(t.Context(), "kill", "-0", pid).Run() != nil
			}, 5*time.Second, 20*time.Millisecond, "dev server still running")
			assertStopped(t, run)
			assert.NotEmpty(t, run.calls(t, "kubectl --context kind-dev -n falco delete"))
		})
	}
}

func TestIngestExitStatusReportsFailures(t *testing.T) {
	for name, tt := range map[string]struct {
		code     string
		wantExit int
	}{"all accepted": {code: "200"}, "rejected": {code: "503", wantExit: 1}} {
		t.Run(name, func(t *testing.T) {
			run := newHelperRun(t, "")
			run.env = append(run.env, "STUB_HTTP_CODE="+tt.code)
			output, got := run.start(t, "ingest-events.sh", "-n", "3", "-q")
			assert.Equal(t, tt.wantExit, got, output)
		})
	}
}

func TestComponentConfigMatchesLiveTestConfig(t *testing.T) {
	raw, err := os.ReadFile("live-test/component.yaml")
	require.NoError(t, err)
	var configMap struct {
		Data map[string]string `yaml:"data"`
	}
	require.NoError(t, yaml.NewDecoder(bytes.NewReader(raw)).Decode(&configMap))

	var embedded, standalone map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(configMap.Data["sidekick.yaml"]), &embedded))
	file, err := os.ReadFile("live-test/sidekick.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(file, &standalone))

	assert.Equal(t, standalone["provisioning"], embedded["provisioning"])
	assert.Equal(t, standalone["ui"], embedded["ui"])
	assert.Equal(t, standalone["runtime_defaults"], embedded["runtime_defaults"])
	assert.Equal(t, map[string]any{"allow_ui_updates": true}, embedded["provisioning"])
}

func TestManifestResourcesCarryTheHelperLabel(t *testing.T) {
	for _, path := range []string{"live-test/component.yaml", "live-test/webhook-receiver.yaml"} {
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		decoder := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var doc struct {
				Metadata struct {
					Labels map[string]string `yaml:"labels"`
					Name   string            `yaml:"name"`
				} `yaml:"metadata"`
				Kind string `yaml:"kind"`
			}
			if err := decoder.Decode(&doc); err != nil {
				break
			}
			assert.Equal(t, "falcosidekick-dev", doc.Metadata.Labels["app.kubernetes.io/part-of"], doc.Kind+"/"+doc.Metadata.Name)
		}
	}
}
