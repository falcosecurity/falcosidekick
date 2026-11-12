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
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"
)

type releaseWorkflow struct {
	On map[string]struct {
		Tags     []string `yaml:"tags"`
		Branches []string `yaml:"branches"`
	} `yaml:"on"`
	// Permissions is nil when the workflow sets none.
	Permissions *map[string]string     `yaml:"permissions"`
	Concurrency *workflowConcurrency   `yaml:"concurrency"`
	Jobs        map[string]*releaseJob `yaml:"jobs"`
}

type releaseJob struct {
	Permissions    *map[string]string   `yaml:"permissions"`
	Concurrency    *workflowConcurrency `yaml:"concurrency"`
	Env            map[string]string    `yaml:"env"`
	With           map[string]string    `yaml:"with"`
	Outputs        map[string]string    `yaml:"outputs"`
	Name           string               `yaml:"name"`
	Uses           string               `yaml:"uses"`
	If             string               `yaml:"if"`
	RunsOn         string               `yaml:"runs-on"`
	Needs          []string             `yaml:"needs"`
	Steps          []releaseStep        `yaml:"steps"`
	TimeoutMinutes int                  `yaml:"timeout-minutes"`
}

// scenarioSuccess is the shim scenario in which every tool succeeds.
const scenarioSuccess = "success"

type workflowConcurrency struct {
	Group            string `yaml:"group"`
	CancelInProgress string `yaml:"cancel-in-progress"`
}

type releaseStep struct {
	With             map[string]string `yaml:"with"`
	Env              map[string]string `yaml:"env"`
	ID               string            `yaml:"id"`
	Name             string            `yaml:"name"`
	Uses             string            `yaml:"uses"`
	Run              string            `yaml:"run"`
	WorkingDirectory string            `yaml:"working-directory"`
}

// permissions returns the job permissions; a job without any fails the test.
func (j *releaseJob) permissions(t *testing.T) map[string]string {
	t.Helper()
	require.NotNil(t, j.Permissions, "job %q sets no permissions", j.Name)
	return *j.Permissions
}

func readWorkflow(t *testing.T, file string) releaseWorkflow {
	t.Helper()
	var workflow releaseWorkflow
	readReleaseYAML(t, ".github/workflows/"+file, &workflow)
	return workflow
}

// stepIndex is the position of the step with that id, or of the first step using that action.
func stepIndex(t *testing.T, job *releaseJob, idOrAction string) int {
	t.Helper()
	require.NotNil(t, job, "missing job")
	for i, step := range job.Steps {
		if step.ID == idOrAction || (step.Uses != "" && strings.HasPrefix(step.Uses, idOrAction+"@")) {
			return i
		}
	}
	t.Fatalf("no step %s", idOrAction)
	return -1
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

func TestReleaseArtifacts(t *testing.T) {
	var config struct {
		Snapshot struct {
			VersionTemplate string `yaml:"version_template"`
		} `yaml:"snapshot"`
		Dist   string `yaml:"dist"`
		Builds []struct {
			ID           string   `yaml:"id"`
			Main         string   `yaml:"main"`
			Binary       string   `yaml:"binary"`
			ModTimestamp string   `yaml:"mod_timestamp"`
			Flags        []string `yaml:"flags"`
			LDFlags      []string `yaml:"ldflags"`
		} `yaml:"builds"`
		DockerSigns []struct {
			Artifacts *string  `yaml:"artifacts"`
			Args      []string `yaml:"args"`
		} `yaml:"docker_signs"`
		Dockers []struct {
			IDs             []string          `yaml:"ids"`
			Dockerfile      string            `yaml:"dockerfile"`
			BuildArgs       map[string]string `yaml:"build_args"`
			Labels          map[string]string `yaml:"labels"`
			LegacyBuildArgs any               `yaml:"build_args_templates"`
			Images          []string          `yaml:"images"`
			Platforms       []string          `yaml:"platforms"`
			Tags            []string          `yaml:"tags"`
		} `yaml:"dockers_v2"`
	}
	readReleaseYAML(t, ".goreleaser.yml", &config)
	require.Equal(t, "dist/release", config.Dist)
	require.Equal(t, "v3-main", config.Snapshot.VersionTemplate)
	require.Len(t, config.DockerSigns, 1)
	require.Nil(t, config.DockerSigns[0].Artifacts)
	// By digest, so the signature names the pushed image even if its tag moves.
	require.Equal(t, []string{"sign", "--recursive", "${artifact}@${digest}"}, config.DockerSigns[0].Args)
	require.Len(t, config.Builds, 2)
	require.Len(t, config.Dockers, 2)
	for _, build := range config.Builds {
		t.Run(build.ID, func(t *testing.T) {
			require.Equal(t, "./cmd/falcosidekick", build.Main)
			require.Contains(t, build.Flags, "-mod=readonly")
			require.Equal(t, "{{ .CommitTimestamp }}", build.ModTimestamp, "reproducible from the commit")
			flags := strings.Join(build.LDFlags, " ")
			prefix := "github.com/falcosecurity/falcosidekick/internal/version."
			for _, assignment := range []string{"Version={{ .Version }}", "Commit={{ .FullCommit }}", "BuildDate={{ .CommitDate }}"} {
				require.Contains(t, flags, "-X "+prefix+assignment)
			}
			require.NotContains(t, flags, ".Env.LDFLAGS")
			ui := build.ID == "falcosidekick"
			require.Equal(t, ui, slices.Contains(build.Flags, "-tags=builtinui"))
			matches := 0
			for _, docker := range config.Dockers {
				if !slices.Contains(docker.IDs, build.ID) {
					continue
				}
				matches++
				require.Equal(t, "Dockerfile", docker.Dockerfile)
				require.Equal(t, build.Binary, docker.BuildArgs["BINARY"])
				require.Nil(t, docker.LegacyBuildArgs)
				require.Equal(t, []string{"falcosecurity/falcosidekick"}, docker.Images)
				require.ElementsMatch(t, []string{"linux/amd64", "linux/arm64"}, docker.Platforms)
				suffix, variant := "", "ui"
				if !ui {
					suffix, variant = "-slim", "slim"
				}
				require.Equal(t, variant, docker.Labels["io.falcosecurity.falcosidekick.variant"])
				require.Equal(t, "falcosidekick", docker.Labels["org.opencontainers.image.title"])
				require.NotContains(t, docker.Labels, "org.opencontainers.image.name", "not an OCI annotation")
				latestMinor := `{{ if eq (index .Env "FSK_LATEST_MINOR") "true" }}`
				latestMajor := `{{ if eq (index .Env "FSK_LATEST_MAJOR") "true" }}`
				require.Equal(t, []string{
					"{{ .Version }}" + suffix,
					latestMinor + "{{ .Major }}.{{ .Minor }}" + suffix + "{{ end }}",
					latestMajor + "{{ .Major }}" + suffix + "{{ end }}",
					latestMajor + "v3-latest" + suffix + "{{ end }}",
				}, docker.Tags)
			}
			require.Equal(t, 1, matches)
		})
	}
}

func TestReleasePublicationRequiresSameRevisionChecks(t *testing.T) {
	for _, name := range []string{"build", "release"} {
		t.Run(name, func(t *testing.T) {
			workflow := readWorkflow(t, name+".yml")
			snapshot := name == "build"
			gates := map[string]string{"checks": "test.yml", "lint": "lint.yml"}
			publishID := "release"
			refGuard := "startsWith(github.ref, 'refs/tags/v3.')"
			if snapshot {
				publishID = "build-snapshot"
				refGuard = "github.ref == 'refs/heads/master'"
			} else {
				gates["e2e"] = "e2e.yml"
			}
			publish, ok := workflow.Jobs[publishID]
			require.True(t, ok, "missing job %s", publishID)
			for id, file := range gates {
				require.Equal(t, "./.github/workflows/"+file, workflow.Jobs[id].Uses, id)
				require.Equal(t, map[string]string{"contents": "read"}, workflow.Jobs[id].permissions(t), id)
				require.Contains(t, publish.Needs, id)
			}
			require.Contains(t, publish.If, "github.repository == 'falcosecurity/falcosidekick' && ",
				"forks must never publish")
			require.Contains(t, publish.If, refGuard)
			require.NotContains(t, publish.If, "always()")
			for _, step := range publish.Steps {
				require.NotContains(t, step.Run, "release/ldflags.sh")
			}
		})
	}
	files, err := filepath.Glob(filepath.Join("..", ".github", "workflows", "*.yml"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, path := range files {
		name := filepath.Base(path)
		workflow := readWorkflow(t, name)
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

// A patch on an older minor must not move the aliases a newer release holds.
func TestReleaseAliasesFollowTheHighestStableTag(t *testing.T) {
	step := releaseWorkflowStep(t, "release.yml", "release", "aliases")
	repo := t.TempDir()
	git := func(args ...string) {
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "c")
	for _, tag := range []string{"v3.0.0", "v3.0.9", "v3.1.2", "v3.2.0-beta.1", "v3.10.0", "v3.10.1-rc.1", "2.35.1"} {
		git("tag", tag)
	}
	for _, tc := range []struct {
		tag, major, minor string
	}{
		{tag: "v3.10.0", major: "true", minor: "true"},
		{tag: "v3.1.2", major: "false", minor: "true"},
		{tag: "v3.0.9", major: "false", minor: "true"},
		{tag: "v3.0.0", major: "false", minor: "false"},
		{tag: "v3.2.0-beta.1", major: "false", minor: "false"},
		{tag: "v3.10.1-rc.1", major: "false", minor: "false"},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			env := filepath.Join(t.TempDir(), "env")
			cmd := exec.CommandContext(t.Context(), "bash", "-c", step.Run)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "GITHUB_REF_NAME="+tc.tag, "GITHUB_ENV="+env)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, string(out))
			written, err := os.ReadFile(env)
			require.NoError(t, err)
			require.Equal(t, "FSK_LATEST_MAJOR="+tc.major+"\nFSK_LATEST_MINOR="+tc.minor+"\n", string(written))
		})
	}
}

func TestReleaseInputsArePinnedAndUpdated(t *testing.T) {
	dockerfile, err := os.ReadFile(filepath.Join("..", "Dockerfile"))
	require.NoError(t, err)
	// A static binary on distroless static: CA certificates and nothing to patch, as UID 65532.
	// A literal FROM with a digest: Dependabot reads FROM lines and does not expand ARG references.
	require.Regexp(t, `(?m)\A(?:#.*\n|\s*\n)*FROM gcr\.io/distroless/static-debian13:nonroot@sha256:[0-9a-f]{64}\n`, string(dockerfile))
	require.Equal(t, 1, strings.Count(string(dockerfile), "\nFROM "), "one stage")
	require.NotRegexp(t, `(?m)^FROM .*\$`, string(dockerfile))
	require.Regexp(t, `(?m)^USER 65532:65532$`, string(dockerfile))
	require.Regexp(t, `(?m)^ENTRYPOINT \["/usr/bin/falcosidekick"\]$`, string(dockerfile))

	var dependabot struct {
		Updates []struct {
			Ecosystem    string `yaml:"package-ecosystem"`
			Directory    string `yaml:"directory"`
			TargetBranch string `yaml:"target-branch"`
		} `yaml:"updates"`
	}
	readReleaseYAML(t, ".github/dependabot.yml", &dependabot)
	var v3 []string
	for _, update := range dependabot.Updates {
		if update.TargetBranch == "" {
			v3 = append(v3, update.Ecosystem+" "+update.Directory)
		}
	}
	require.ElementsMatch(t, []string{"gomod /", "github-actions /", "docker /", "bun /ui"}, v3)
}

// Each check runs once per event: pull requests trigger test and lint, build and release call them.
func TestReleaseChecksIncludeUITestsAndLint(t *testing.T) {
	tests, lint := readWorkflow(t, "test.yml"), readWorkflow(t, "lint.yml")
	for name, workflow := range map[string]releaseWorkflow{"test": tests, "lint": lint} {
		require.Contains(t, workflow.On, "workflow_call", name)
		require.Contains(t, workflow.On, "pull_request", name)
		require.NotContains(t, workflow.On, "push", "%s: build and release call it on push", name)
	}
	for id, job := range tests.Jobs {
		require.Empty(t, job.Uses, "test.yml job %s: build and release call lint.yml themselves", id)
		for _, step := range job.Steps {
			require.NotContains(t, step.Run, "bun run lint", "UI eslint in lint.yml runs it")
		}
	}
	ui := releaseWorkflowStep(t, "test.yml", "unit-tests", "ui-tests")
	require.Equal(t, "ui", ui.WorkingDirectory)
	require.Equal(t, "bun test", strings.TrimSpace(ui.Run))
	check := releaseWorkflowStep(t, "test.yml", "unit-tests", "release-config")
	require.Equal(t, "check", check.With["args"], "goreleaser reads the default .goreleaser.yml")
}

// Pull requests build the release images without publishing them.
func TestPullRequestsBuildTheImages(t *testing.T) {
	var build releaseWorkflow
	readReleaseYAML(t, ".github/workflows/build-image.yml", &build)
	require.Contains(t, build.On, "pull_request")
	require.Equal(t, "build-image", build.Jobs["build-image"].Name, "the required check context")
	snapshot := releaseWorkflowStep(t, "build-image.yml", "build-image", "snapshot")
	require.Equal(t, "release --snapshot --clean --skip=publish,sign,sbom", snapshot.With["args"])
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "build-image.yml"))
	require.NoError(t, err)
	require.NotContains(t, string(raw), "secrets.", "pull requests from forks get no secrets")
	require.NotContains(t, string(raw), "login-action")
}

// A release never waits behind, or is replaced by, a snapshot or another tag.
func TestReleaseAndSnapshotConcurrency(t *testing.T) {
	release := readWorkflow(t, "release.yml").Jobs["release"]
	snapshot := readWorkflow(t, "build.yml").Jobs["build-snapshot"]
	require.NotNil(t, release.Concurrency)
	require.NotNil(t, snapshot.Concurrency)
	require.Equal(t, workflowConcurrency{Group: "release-${{ github.ref }}", CancelInProgress: "false"}, *release.Concurrency)
	require.Equal(t, workflowConcurrency{Group: "snapshot-${{ github.ref }}", CancelInProgress: "false"}, *snapshot.Concurrency)
	for _, name := range []string{"release.yml", "build.yml"} {
		require.Nil(t, readWorkflow(t, name).Concurrency, "%s: a workflow group would also hold the called checks", name)
	}
}

func TestReleaseRegistryLogin(t *testing.T) {
	t.Run("snapshot logs in after the build, right before the push", func(t *testing.T) {
		job := readWorkflow(t, "build.yml").Jobs["build-snapshot"]
		snapshot, login := stepIndex(t, job, "snapshot"), stepIndex(t, job, "login")
		publish, sign := stepIndex(t, job, "publish-snapshot"), stepIndex(t, job, "sign-snapshot")
		require.Equal(t, []int{snapshot + 1, login + 1, publish + 1}, []int{login, publish, sign})
		require.True(t, strings.HasPrefix(job.Steps[login].Uses, "docker/login-action@"))
		require.Empty(t, job.Steps[snapshot].Env, "a snapshot publishes nothing and needs no token")
		require.Equal(t, "release --snapshot --clean --skip=sign", job.Steps[snapshot].With["args"])
	})
	t.Run("release token outlives the goreleaser push", func(t *testing.T) {
		job := readWorkflow(t, "release.yml").Jobs["release"]
		login, release := stepIndex(t, job, "login"), stepIndex(t, job, "run-goreleaser")
		require.Equal(t, login+1, release)
		require.Equal(t, "3600", job.Steps[login].Env["DOCKERHUB_OIDC_EXPIREIN"])
		require.Equal(t, "${{ secrets.GITHUB_TOKEN }}", job.Steps[release].Env["GITHUB_TOKEN"])
	})
}

func TestReleaseSnapshotSigning(t *testing.T) {
	step := releaseWorkflowStep(t, "build.yml", "build-snapshot", "sign-snapshot")
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tools := map[string]string{
		"docker": `
printf 'docker %s\n' "$*" >> "$CALLS"
[[ "$1 $2 $3" == 'buildx imagetools inspect' ]] || exit 2
case "$SCENARIO" in
  no-digest) echo '{}' ;;
  *) printf '{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"%s"}\n' "$DIGEST" ;;
esac
`,
		"cosign": `
printf 'cosign %s\n' "$*" >> "$CALLS"
[[ "$SCENARIO" != cosign-failure ]] || exit 7
`,
	}
	for _, scenario := range []string{scenarioSuccess, "no-digest", "cosign-failure"} {
		t.Run(scenario, func(t *testing.T) {
			output, dir, err := runReleaseScriptWith(t, step.Run, tools, "DIGEST="+digest, "SCENARIO="+scenario)
			calls, readErr := os.ReadFile(filepath.Join(dir, "calls"))
			require.NoError(t, readErr)
			log := string(calls)
			if scenario != scenarioSuccess {
				require.Error(t, err, output)
				if scenario == "no-digest" {
					require.NotContains(t, log, "cosign ")
				}
				return
			}
			require.NoError(t, err, output)
			for _, suffix := range []string{"", "-slim"} {
				require.Contains(t, log, "docker buildx imagetools inspect --format {{json .Manifest}} falcosecurity/falcosidekick:v3-main"+suffix+"\n")
			}
			require.Equal(t, 2, strings.Count(log, "cosign sign --yes --recursive falcosecurity/falcosidekick@"+digest+"\n"), log)
		})
	}
}

// SLSA provenance covers the release files.
func TestReleaseProvenance(t *testing.T) {
	workflow := readWorkflow(t, "release.yml")
	release, provenance := workflow.Jobs["release"], workflow.Jobs["provenance"]
	require.Equal(t, "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0", provenance.Uses)
	require.Equal(t, []string{"release"}, provenance.Needs)
	require.Equal(t, map[string]string{"actions": "read", "id-token": "write", "contents": "write"}, provenance.permissions(t))
	require.Equal(t, map[string]string{
		"base64-subjects": "${{ needs.release.outputs.hashes }}",
		"upload-assets":   "true",
		"upload-tag-name": "${{ needs.release.outputs.tag_name }}",
	}, provenance.With)
	require.Equal(t, map[string]string{
		"hashes":   "${{ steps.hash.outputs.hashes }}",
		"tag_name": "${{ github.ref_name }}",
	}, release.Outputs)
	require.Equal(t, stepIndex(t, release, "run-goreleaser")+1, stepIndex(t, release, "hash"))

	step := releaseWorkflowStep(t, "release.yml", "release", "hash")
	require.Equal(t, "${{ steps.run-goreleaser.outputs.artifacts }}", step.Env["ARTIFACTS"])
	const checksums = "1111  falcosidekick_3.0.0_linux_amd64.tar.gz\n2222  falcosidekick_3.0.0_linux_arm64.tar.gz\n"
	archive := `{"type":"Archive","path":"dist/release/falcosidekick_3.0.0_linux_amd64.tar.gz"}`
	checksum := `{"type":"Checksum","path":"dist/release/falcosidekick-checksums.txt"}`
	for _, tc := range []struct {
		name, artifacts, content string
		wantError                bool
	}{
		{name: "one checksum file", artifacts: "[" + archive + "," + checksum + "]", content: checksums},
		{name: "no checksum file", artifacts: "[" + archive + "]", content: checksums, wantError: true},
		{name: "two checksum files", artifacts: "[" + checksum + "," + checksum + "]", content: checksums, wantError: true},
		{name: "empty checksum file", artifacts: "[" + checksum + "]", wantError: true},
		{name: "no artifacts output", artifacts: "", content: checksums, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "dist", "release"), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "dist", "release", "falcosidekick-checksums.txt"), []byte(tc.content), 0o600))
			out := filepath.Join(dir, "github-output")
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", step.Run)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "ARTIFACTS="+tc.artifacts, "GITHUB_OUTPUT="+out)
			combined, err := cmd.CombinedOutput()
			if tc.wantError {
				require.Error(t, err, string(combined))
				return
			}
			require.NoError(t, err, string(combined))
			written, err := os.ReadFile(out)
			require.NoError(t, err)
			require.Equal(t, "hashes="+base64.StdEncoding.EncodeToString([]byte(checksums))+"\n", string(written))
		})
	}
}

func runReleaseScript(t *testing.T, script, tool, shim string, env ...string) (output, dir string, err error) {
	t.Helper()
	return runReleaseScriptWith(t, script, map[string]string{tool: shim}, env...)
}

// runReleaseScriptWith runs script with each tool replaced by its shim; shims append to $CALLS.
func runReleaseScriptWith(t *testing.T, script string, tools map[string]string, env ...string) (output, dir string, err error) {
	t.Helper()
	dir = t.TempDir()
	for tool, shim := range tools {
		require.NoError(t, os.WriteFile(filepath.Join(dir, tool), []byte("#!/bin/bash\nset -euo pipefail\n"+shim), 0o700))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "calls"), nil, 0o600))
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
	step := releaseWorkflowStep(t, "test.yml", "unit-tests", "coverage")
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
	step := releaseWorkflowStep(t, "build.yml", "build-snapshot", "publish-snapshot")
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
    printf 'falcosidekick v3-main (commit: %s, built: 2026-10-05T00:00:00Z, go: go1.26.7)\n' "$GITHUB_SHA" ;;
  push) [[ "$SCENARIO" != push-failure ]] || exit 8 ;;
  tag|buildx) ;;
  *) exit 2 ;;
esac
`
	for _, scenario := range []string{scenarioSuccess, "revision-mismatch", "smoke-failure", "push-failure"} {
		t.Run(scenario, func(t *testing.T) {
			output, dir, err := runReleaseScript(t, step.Run, "docker", shim, "GITHUB_SHA="+sha, "SCENARIO="+scenario)
			calls, readErr := os.ReadFile(filepath.Join(dir, "calls"))
			require.NoError(t, readErr)
			log := string(calls)
			if scenario != scenarioSuccess {
				require.Error(t, err, output)
				require.NotContains(t, log, "buildx imagetools create")
				if scenario != "push-failure" {
					require.NotContains(t, log, "push ")
				}
				return
			}
			require.NoError(t, err, output)
			require.NotContains(t, log, "public.ecr.aws", "images are published to Docker Hub only")
			for _, image := range []string{"falcosecurity/falcosidekick"} {
				for _, suffix := range []string{"", "-slim"} {
					for _, arch := range []string{"amd64", "arm64"} {
						local := image + ":v3-main" + suffix + "-" + arch
						remote := image + ":v3-main-" + sha + suffix + "-" + arch
						require.Contains(t, log, "tag "+local+" "+remote+"\n")
						require.Contains(t, log, "push "+remote+"\n")
					}
					manifest := "buildx imagetools create --tag " + image + ":v3-main" + suffix
					for _, arch := range []string{"amd64", "arm64"} {
						manifest += " " + image + ":v3-main-" + sha + suffix + "-" + arch
					}
					require.Contains(t, log, manifest+"\n")
				}
			}
			require.NotRegexp(t, `:latest(\s|$)`, log)
			require.NotContains(t, log, "v3-latest", "master never publishes a release alias")
			require.Less(t, strings.LastIndex(log, "push "), strings.Index(log, "buildx imagetools create"))
		})
	}
}
