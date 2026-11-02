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

package hacktesting

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type releaseWorkflow struct {
	On map[string]struct {
		Tags []string `yaml:"tags"`
	} `yaml:"on"`
	Jobs map[string]struct {
		Uses        string            `yaml:"uses"`
		Needs       []string          `yaml:"needs"`
		If          string            `yaml:"if"`
		Permissions map[string]string `yaml:"permissions"`
		Steps       []releaseStep     `yaml:"steps"`
	} `yaml:"jobs"`
}

type releaseStep struct {
	With             map[string]string `yaml:"with"`
	ID               string            `yaml:"id"`
	Uses             string            `yaml:"uses"`
	Run              string            `yaml:"run"`
	WorkingDirectory string            `yaml:"working-directory"`
}

func readReleaseYAML(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", path))
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(data, target))
}

func releaseWorkflowStep(t *testing.T, file, jobID, stepID string) releaseStep {
	t.Helper()
	var workflow releaseWorkflow
	readReleaseYAML(t, ".github/workflows/"+file, &workflow)
	job, ok := workflow.Jobs[jobID]
	require.True(t, ok, "missing job %s", jobID)
	for _, step := range job.Steps {
		if step.ID == stepID {
			return step
		}
	}
	t.Fatalf("missing step %s in %s", stepID, file)
	return releaseStep{}
}

func TestReleaseV3Artifacts(t *testing.T) {
	var config struct {
		Dist   string `yaml:"dist"`
		Builds []struct {
			ID      string   `yaml:"id"`
			Main    string   `yaml:"main"`
			Binary  string   `yaml:"binary"`
			Flags   []string `yaml:"flags"`
			LDFlags []string `yaml:"ldflags"`
		} `yaml:"builds"`
		Dockers []struct {
			IDs             []string          `yaml:"ids"`
			Dockerfile      string            `yaml:"dockerfile"`
			BuildArgs       map[string]string `yaml:"build_args"`
			LegacyBuildArgs any               `yaml:"build_args_templates"`
			Images          []string          `yaml:"images"`
			Platforms       []string          `yaml:"platforms"`
			Tags            []string          `yaml:"tags"`
		} `yaml:"dockers_v2"`
	}
	readReleaseYAML(t, ".goreleaser.v3.yml", &config)
	require.Equal(t, "dist/release", config.Dist)
	require.Len(t, config.Builds, 2)
	require.Len(t, config.Dockers, 2)
	for _, build := range config.Builds {
		t.Run(build.ID, func(t *testing.T) {
			require.Equal(t, "./cmd/falcosidekick", build.Main)
			require.Contains(t, build.Flags, "-mod=readonly")
			flags := strings.Join(build.LDFlags, " ")
			prefix := "github.com/falcosecurity/falcosidekick/internal/version."
			for _, assignment := range []string{"Version={{ .Version }}", "Commit={{ .FullCommit }}", "BuildDate={{ .Date }}"} {
				require.Contains(t, flags, "-X "+prefix+assignment)
			}
			require.NotContains(t, flags, ".Env.LDFLAGS")
			ui := build.ID == "falcosidekick-v3"
			require.Equal(t, ui, slices.Contains(build.Flags, "-tags=builtinui"))
			matches := 0
			for _, docker := range config.Dockers {
				if !slices.Contains(docker.IDs, build.ID) {
					continue
				}
				matches++
				require.Equal(t, "Dockerfile.v3", docker.Dockerfile)
				require.Equal(t, build.Binary, docker.BuildArgs["BINARY"])
				require.Nil(t, docker.LegacyBuildArgs)
				require.Equal(t, []string{"falcosecurity/falcosidekick", "public.ecr.aws/falcosecurity/falcosidekick"}, docker.Images)
				require.ElementsMatch(t, []string{"linux/amd64", "linux/arm64"}, docker.Platforms)
				if ui {
					require.Equal(t, "ui", docker.BuildArgs["VARIANT"])
					require.Contains(t, docker.Tags, "v3-latest")
				} else {
					require.Equal(t, "slim", docker.BuildArgs["VARIANT"])
					require.Contains(t, docker.Tags, "v3-latest-slim")
				}
			}
			require.Equal(t, 1, matches)
		})
	}
}

func TestReleasePublicationRequiresSameRevisionChecks(t *testing.T) {
	for _, name := range []string{"v3-build", "v3-release"} {
		t.Run(name, func(t *testing.T) {
			var workflow releaseWorkflow
			readReleaseYAML(t, ".github/workflows/"+name+".yml", &workflow)
			checks := workflow.Jobs["checks"]
			require.Equal(t, "./.github/workflows/v3-test.yml", checks.Uses)
			require.Equal(t, "read", checks.Permissions["contents"])
			publishID := "v3-release"
			refGuard := "startsWith(github.ref, 'refs/tags/v3.')"
			if name == "v3-build" {
				publishID = "v3-build-snapshot"
				refGuard = "github.ref == 'refs/heads/master'"
			}
			publish := workflow.Jobs[publishID]
			require.Contains(t, publish.Needs, "checks")
			require.Contains(t, publish.If, refGuard)
			require.NotContains(t, publish.If, "always()")
			for _, step := range publish.Steps {
				require.NotContains(t, step.Run, "release/ldflags.sh")
			}
		})
	}
	for _, name := range []string{"v3-build", "v3-release", "v3-test", "v3-lint"} {
		var workflow releaseWorkflow
		readReleaseYAML(t, ".github/workflows/"+name+".yml", &workflow)
		for _, job := range workflow.Jobs {
			for _, step := range job.Steps {
				if strings.HasPrefix(step.Uses, "actions/checkout@") {
					require.Equal(t, "${{ github.sha }}", step.With["ref"], name)
					require.Equal(t, "false", step.With["persist-credentials"], name)
				}
				if strings.HasPrefix(step.Uses, "goreleaser/goreleaser-action@") {
					require.Equal(t, "v2.18.2", step.With["version"], name)
				}
			}
		}
	}
}

func TestReleaseChecksIncludeUITestsAndLint(t *testing.T) {
	var tests, lint releaseWorkflow
	readReleaseYAML(t, ".github/workflows/v3-test.yml", &tests)
	readReleaseYAML(t, ".github/workflows/v3-lint.yml", &lint)
	require.Contains(t, tests.On, "workflow_call")
	require.Contains(t, lint.On, "workflow_call")
	require.Equal(t, "./.github/workflows/v3-lint.yml", tests.Jobs["v3-lint"].Uses)
	ui := releaseWorkflowStep(t, "v3-test.yml", "v3-unit-tests", "ui-tests")
	require.Equal(t, "ui", ui.WorkingDirectory)
	require.Equal(t, "bun test", strings.TrimSpace(ui.Run))
	check := releaseWorkflowStep(t, "v3-test.yml", "v3-unit-tests", "release-config")
	require.Equal(t, "check --config .goreleaser.v3.yml", check.With["args"])
}

func runReleaseScript(t *testing.T, script, tool, shim string, env ...string) (output, dir string, err error) {
	t.Helper()
	dir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, tool), []byte("#!/bin/bash\nset -euo pipefail\n"+shim), 0o700))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-euo", "pipefail", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "CALLS="+filepath.Join(dir, "calls"))
	cmd.Env = append(cmd.Env, env...)
	combined, err := cmd.CombinedOutput()
	return string(combined), dir, err
}

func TestReleaseCoverageThreshold(t *testing.T) {
	step := releaseWorkflowStep(t, "v3-test.yml", "v3-unit-tests", "coverage")
	const shim = `
if [[ "$1" == test ]]; then
  [[ "$TEST_FAIL" != yes ]] || exit 9
  printf '%s\n' "$*" >> "$CALLS"
  exit 0
fi
[[ "$1 $2" == 'tool cover' ]] || exit 2
[[ "$REPORT_FAIL" != yes ]] || exit 8
coverage="$API_COVERAGE"
[[ "$*" != *falcosidekick.out* ]] || coverage="$CMD_COVERAGE"
printf '%s\n' 'example.go:10: function 100.0%'
[[ "$coverage" != missing ]] || exit 0
printf 'total: (statements) %s\n' "$coverage"
`
	for _, tc := range []struct {
		name, api, cmd, testFail, reportFail string
		wantError                            bool
	}{
		{name: "boundary", api: "80.0%", cmd: "80.0%"},
		{name: "above", api: "93.2%", cmd: "100.0%"},
		{name: "low-api", api: "79.9%", cmd: "100.0%", wantError: true},
		{name: "low-command", api: "100.0%", cmd: "79.9%", wantError: true},
		{name: "missing-total", api: "missing", cmd: "100.0%", wantError: true},
		{name: "malformed", api: "wat%", cmd: "100.0%", wantError: true},
		{name: "out-of-range", api: "101%", cmd: "100.0%", wantError: true},
		{name: "tests-failed", api: "100.0%", cmd: "100.0%", testFail: "yes", wantError: true},
		{name: "report-failed", api: "100.0%", cmd: "100.0%", reportFail: "yes", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, dir, err := runReleaseScript(t, step.Run, "go", shim,
				"API_COVERAGE="+tc.api, "CMD_COVERAGE="+tc.cmd, "TEST_FAIL="+tc.testFail, "REPORT_FAIL="+tc.reportFail)
			if tc.wantError {
				require.Error(t, err, output)
				return
			}
			require.NoError(t, err, output)
			calls, err := os.ReadFile(filepath.Join(dir, "calls"))
			require.NoError(t, err)
			require.Contains(t, string(calls), "-coverprofile=dist/coverage/api.out ./internal/api")
			require.Contains(t, string(calls), "-coverprofile=dist/coverage/falcosidekick.out ./cmd/falcosidekick")
		})
	}
}

func TestReleaseSnapshotPublication(t *testing.T) {
	step := releaseWorkflowStep(t, "v3-build.yml", "v3-build-snapshot", "publish-snapshot")
	const sha = "0123456789abcdef0123456789abcdef01234567"
	const shim = `
printf '%s\n' "$*" >> "$CALLS"
case "$1" in
  image)
    case "$*" in
      *org.opencontainers.image.revision*)
        [[ "$SCENARIO" != revision-mismatch ]] || { echo wrong; exit 0; }
        echo "$GITHUB_SHA" ;;
      *io.falcosecurity.falcosidekick.variant*)
        [[ "$*" != *-slim-* ]] && echo ui || echo slim ;;
      *) [[ "$*" != *-arm64 ]] && echo linux/amd64 || echo linux/arm64 ;;
    esac ;;
  run)
    [[ "$SCENARIO" != smoke-failure ]] || exit 7
    printf 'falcosidekick v3-latest (commit: %s, built: 2026-10-05T00:00:00Z, go: go1.26.7)\n' "$GITHUB_SHA" ;;
  push) [[ "$SCENARIO" != push-failure ]] || exit 8 ;;
  tag|buildx) ;;
  *) exit 2 ;;
esac
`
	for _, scenario := range []string{"success", "revision-mismatch", "smoke-failure", "push-failure"} {
		t.Run(scenario, func(t *testing.T) {
			output, dir, err := runReleaseScript(t, step.Run, "docker", shim, "GITHUB_SHA="+sha, "SCENARIO="+scenario)
			calls, readErr := os.ReadFile(filepath.Join(dir, "calls"))
			require.NoError(t, readErr)
			log := string(calls)
			if scenario != "success" {
				require.Error(t, err, output)
				require.NotContains(t, log, "buildx imagetools create")
				if scenario != "push-failure" {
					require.NotContains(t, log, "push ")
				}
				return
			}
			require.NoError(t, err, output)
			for _, image := range []string{"falcosecurity/falcosidekick", "public.ecr.aws/falcosecurity/falcosidekick"} {
				for _, suffix := range []string{"", "-slim"} {
					for _, arch := range []string{"amd64", "arm64"} {
						local := image + ":v3-latest" + suffix + "-" + arch
						remote := image + ":v3-" + sha + suffix + "-" + arch
						require.Contains(t, log, "tag "+local+" "+remote+"\n")
						require.Contains(t, log, "push "+remote+"\n")
					}
					manifest := "buildx imagetools create --tag " + image + ":v3-latest" + suffix
					for _, arch := range []string{"amd64", "arm64"} {
						manifest += " " + image + ":v3-" + sha + suffix + "-" + arch
					}
					require.Contains(t, log, manifest+"\n")
				}
			}
			require.NotRegexp(t, `:latest(\s|$)`, log)
			require.Less(t, strings.LastIndex(log, "push "), strings.Index(log, "buildx imagetools create"))
		})
	}
}
