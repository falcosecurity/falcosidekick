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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func workflowFiles(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", ".github", "workflows", "*.yml"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, filepath.Base(path))
	}
	return names
}

// slsaGenerator verifies its own ref, so it is the one action referenced by tag.
const slsaGenerator = "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"

// actionFloors are the lowest versions a pin may use, from upstream master on 2026-11-09; setup-bun,
// which master does not use, has its own.
var actionFloors = map[string]string{
	"actions/checkout":                  "v7.0.1",
	"actions/setup-go":                  "v7.0.0",
	"anchore/sbom-action/download-syft": "v0.24.3",
	"docker/login-action":               "v4.7.0",
	"docker/setup-buildx-action":        "v4.4.1",
	"docker/setup-qemu-action":          "v4.4.0",
	"golangci/golangci-lint-action":     "v9.3.0",
	"goreleaser/goreleaser-action":      "v7.3.0",
	"oven-sh/setup-bun":                 "v2.2.0",
	"sigstore/cosign-installer":         "v4.1.2",
}

// mislabeledPins are commits whose version label is wrong; no pin may use them.
var mislabeledPins = map[string]string{
	"4bc047ad259df6fc24a6c9b0f9a0cb08cf17fbe5": "oven-sh/setup-bun v2.0.1, once commented as v2.0.2",
}

var (
	usesLine   = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*(\S+)(?:\s+#\s*(.*\S))?\s*$`)
	commitPin  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	releaseTag = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)
)

func semver(t *testing.T, version string) [3]int {
	t.Helper()
	m := releaseTag.FindStringSubmatch(version)
	require.NotNil(t, m, "%q is not vX.Y.Z", version)
	var v [3]int
	for i := range v {
		n, err := strconv.Atoi(m[i+1])
		require.NoError(t, err)
		v[i] = n
	}
	return v
}

func versionAtLeast(t *testing.T, version, floor string) bool {
	t.Helper()
	v, f := semver(t, version), semver(t, floor)
	for i := range v {
		if v[i] != f[i] {
			return v[i] > f[i]
		}
	}
	return true
}

// Every action is pinned by commit with its exact version, the same everywhere, at or above upstream master.
func TestWorkflowActionsArePinned(t *testing.T) {
	type pin struct{ commit, version, file string }
	seen := map[string]pin{}
	for _, file := range workflowFiles(t) {
		raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", file))
		require.NoError(t, err)
		for n, line := range strings.Split(string(raw), "\n") {
			m := usesLine.FindStringSubmatch(line)
			if len(m) < 3 || strings.HasPrefix(m[1], "./") {
				continue
			}
			where := fmt.Sprintf("%s:%d", file, n+1)
			action, ref, ok := strings.Cut(m[1], "@")
			require.True(t, ok, "%s: %s has no ref", where, m[1])
			if action == slsaGenerator {
				semver(t, ref)
				require.Empty(t, m[2], where)
				continue
			}
			require.Regexp(t, commitPin, ref, "%s: %s is not pinned by commit", where, action)
			require.NotContains(t, mislabeledPins, ref, "%s: %s", where, mislabeledPins[ref])
			semver(t, m[2])
			if floor, ok := actionFloors[action]; ok {
				assert.True(t, versionAtLeast(t, m[2], floor), "%s: %s %s is below upstream %s", where, action, m[2], floor)
			}
			if prev, ok := seen[action]; ok {
				assert.Equal(t, prev.commit+" "+prev.version, ref+" "+m[2], "%s: %s differs from %s", where, action, prev.file)
				continue
			}
			seen[action] = pin{commit: ref, version: m[2], file: where}
		}
	}
	for action := range actionFloors {
		assert.Contains(t, seen, action, "floor for an action no workflow uses")
	}
}

func TestWorkflowJobsHaveTimeoutsAndPermissions(t *testing.T) {
	for _, file := range workflowFiles(t) {
		workflow := readWorkflow(t, file)
		require.NotNil(t, workflow.Permissions, "%s: top-level permissions", file)
		require.Empty(t, *workflow.Permissions, "%s: jobs ask for what they need", file)
		for id, job := range workflow.Jobs {
			where := file + " " + id
			require.NotNil(t, job.Permissions, "%s: job permissions", where)
			if job.Uses != "" {
				require.Zero(t, job.TimeoutMinutes, "%s: a called workflow sets its own timeouts", where)
				continue
			}
			require.Equal(t, "ubuntu-latest", job.RunsOn, where)
			require.Positive(t, job.TimeoutMinutes, "%s: timeout-minutes", where)
			require.LessOrEqual(t, job.TimeoutMinutes, 180, where)
		}
	}
}

// requiredChecks are the contexts falcosecurity/test-infra requires on master.
var requiredChecks = map[string]map[string]string{
	"test.yml":        {"unit-tests": "Go + UI tests"},
	"lint.yml":        {"golangci": "golangci-lint", "ui-lint": "UI eslint"},
	"e2e.yml":         {"self-contained": "e2e self-contained outputs"},
	"build-image.yml": {"build-image": "build-image"},
}

func TestRequiredCheckNames(t *testing.T) {
	for file, jobs := range requiredChecks {
		workflow := readWorkflow(t, file)
		pr, ok := workflow.On["pull_request"]
		require.True(t, ok, "%s runs on pull requests", file)
		require.Equal(t, []string{"master"}, pr.Branches, file)
		for id, name := range jobs {
			job, ok := workflow.Jobs[id]
			require.True(t, ok, "%s: missing job %s", file, id)
			require.Equal(t, name, job.Name, "%s %s: the required context", file, id)
			require.Empty(t, job.If, "%s %s: a skipped required check never reports", file, id)
		}
	}
}

func TestPullRequestChecksCancelOlderRuns(t *testing.T) {
	for name, prefix := range map[string]string{"test": "tests", "lint": "lint"} {
		workflow := readWorkflow(t, name+".yml")
		require.NotNil(t, workflow.Concurrency, name)
		require.Equal(t, workflowConcurrency{
			Group:            prefix + "-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
			CancelInProgress: "${{ github.event_name == 'pull_request' }}",
		}, *workflow.Concurrency, "%s: only pull requests share a group; called runs never wait or cancel", name)
	}
}

func TestE2EServiceJobsFailOnMissingServices(t *testing.T) {
	harness, err := os.ReadFile(filepath.Join("..", "test", "e2e", "harness_test.go"))
	require.NoError(t, err)
	require.Contains(t, string(harness), `requireSwitch = "FALCOSIDEKICK_E2E_REQUIRE"`)
	for id, job := range readWorkflow(t, "e2e.yml").Jobs {
		runsE2E, postgresRequired := false, false
		for _, step := range job.Steps {
			runsE2E = runsE2E || strings.Contains(step.Run, "./test/e2e/")
			postgresRequired = postgresRequired || step.Env["FALCOSIDEKICK_E2E_POSTGRES_REQUIRED"] == "1"
		}
		switch {
		case id == "self-contained":
			require.NotContains(t, job.Env, "FALCOSIDEKICK_E2E_REQUIRE", "the self-contained run skips service tests")
		case runsE2E:
			require.Equal(t, "1", job.Env["FALCOSIDEKICK_E2E_REQUIRE"], "e2e job %s", id)
		default:
			require.True(t, postgresRequired, "e2e job %s runs no ./test/e2e/ test and does not require postgres", id)
		}
	}
}

// One Go version, from go.mod, and one exact Bun version, from ui/package.json.
func TestWorkflowToolVersions(t *testing.T) {
	var pkg struct {
		PackageManager string `json:"packageManager"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "ui", "package.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &pkg))
	require.Regexp(t, `^bun@\d+\.\d+\.\d+$`, pkg.PackageManager)
	helm := map[string]string{}
	for _, file := range workflowFiles(t) {
		for id, job := range readWorkflow(t, file).Jobs {
			for _, step := range job.Steps {
				where := file + " " + id
				switch {
				case strings.HasPrefix(step.Uses, "actions/setup-go@"):
					require.Equal(t, map[string]string{"go-version-file": "go.mod"}, without(step.With, "cache"), where)
				case strings.HasPrefix(step.Uses, "oven-sh/setup-bun@"):
					require.Equal(t, map[string]string{"bun-version-file": "ui/package.json"}, step.With, where)
				case strings.HasPrefix(step.Uses, "azure/setup-helm@"):
					helm[where] = step.With["version"]
				}
			}
		}
	}
	require.NotEmpty(t, helm)
	for where, version := range helm {
		semver(t, version)
		require.Equal(t, helm["chart.yml chart-testing"], version, "%s: one helm version, the chart job's", where)
	}
}

func without(m map[string]string, key string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if k != key {
			out[k] = v
		}
	}
	return out
}

// Lint covers the files behind build tags, in CI and in make lint.
func TestLintCoversTaggedFiles(t *testing.T) {
	lint := readWorkflow(t, "lint.yml").Jobs["golangci"]
	packages := "./internal/... ./cmd/... ./ui ./hack/..."
	require.Equal(t, packages, lint.Steps[stepIndex(t, lint, "lint-default")].With["args"])
	require.Equal(t, "--build-tags=builtinui,e2e,integration "+packages+" ./test/...", lint.Steps[stepIndex(t, lint, "lint-tagged")].With["args"])
	require.Less(t, stepIndex(t, lint, "oven-sh/setup-bun"), stepIndex(t, lint, "lint-tagged"), "builtinui embeds ui/dist")
	makefile, err := os.ReadFile(filepath.Join("..", "Makefile"))
	require.NoError(t, err)
	require.Contains(t, string(makefile), "LINT_TAGS := builtinui,e2e,integration\n")
	require.Contains(t, string(makefile), "\tgolangci-lint run $(PACKAGES) ./ui ./hack/...\n")
	require.Contains(t, string(makefile), "\tgolangci-lint run --build-tags=$(LINT_TAGS) $(PACKAGES) ./ui ./hack/... ./test/...\n")
}

func TestLintChecksModulesVulnerabilitiesAndWorkflows(t *testing.T) {
	jobs := readWorkflow(t, "lint.yml").Jobs
	for id, target := range map[string]string{"go-mod": "go.mod.check", "govulncheck": "govulncheck", "actionlint": "actionlint"} {
		job, ok := jobs[id]
		require.True(t, ok, "lint.yml job %s", id)
		require.Equal(t, "make "+target, strings.TrimSpace(job.Steps[len(job.Steps)-1].Run), id)
	}
	makefile, err := os.ReadFile(filepath.Join("..", "Makefile"))
	require.NoError(t, err)
	for _, rule := range []string{
		"\t$(GO) mod verify\n\t$(GO) mod tidy -diff\n",
		"\t$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) -test -tags=e2e,integration ./...\n",
		"\t$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)\n",
	} {
		require.Contains(t, string(makefile), rule)
	}
	require.Regexp(t, `(?m)^verify: .*\bgo\.mod\.check govulncheck actionlint\b`, string(makefile))
}

// The header year is any year: a fixed {{ YEAR }} fails every file on 1 January.
func TestGoHeaderAcceptsAnyYear(t *testing.T) {
	var config struct {
		Linters struct {
			Settings struct {
				GoHeader struct {
					Values struct {
						Regexp map[string]string `yaml:"regexp"`
					} `yaml:"values"`
					Template string `yaml:"template"`
				} `yaml:"goheader"`
			} `yaml:"settings"`
		} `yaml:"linters"`
	}
	readReleaseYAML(t, ".golangci.yml", &config)
	header := config.Linters.Settings.GoHeader
	require.NotContains(t, header.Template, "{{ YEAR }}")
	require.True(t, strings.HasPrefix(header.Template, "Copyright (C) {{ COPYRIGHT_YEAR }} {{ AUTHORS }}\n"))
	year := regexp.MustCompile(`^(?:` + header.Values.Regexp["COPYRIGHT_YEAR"] + `)$`)
	for _, y := range []string{"2023", "2026", "2027", "2099"} {
		require.Regexp(t, year, y)
	}
	require.NotRegexp(t, year, "{{ YEAR }}")
}

func TestE2EImagesArePinned(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "e2e.yml"))
	require.NoError(t, err)
	redis := regexp.MustCompile(`\bredis:(\S+)`).FindAllStringSubmatch(string(raw), -1)
	require.Len(t, redis, 2)
	for _, m := range redis {
		require.Regexp(t, `^\d+\.\d+\.\d+$`, m[1], "redis image")
	}
	require.NotRegexp(t, `:latest\b`, string(raw))
}

func TestChartJobLintsAndInstallsTheChart(t *testing.T) {
	var ct struct {
		Remote              string   `yaml:"remote"`
		TargetBranch        string   `yaml:"target-branch"`
		HelmExtraArgs       string   `yaml:"helm-extra-args"`
		ChartDirs           []string `yaml:"chart-dirs"`
		ValidateMaintainers bool     `yaml:"validate-maintainers"`
	}
	readReleaseYAML(t, "ct.yaml", &ct)
	require.Equal(t, "origin", ct.Remote)
	require.Equal(t, "master", ct.TargetBranch)
	require.Equal(t, []string{"chart"}, ct.ChartDirs)
	require.Equal(t, "--timeout 800s", ct.HelmExtraArgs)

	workflow := readWorkflow(t, "chart.yml")
	require.Contains(t, workflow.On, "pull_request")
	job := workflow.Jobs["chart-testing"]
	runs := make([]string, 0, len(job.Steps))
	for _, step := range job.Steps {
		runs = append(runs, strings.TrimSpace(step.Run))
	}
	all := strings.Join(runs, "\n")
	require.Contains(t, runs, "ct lint --config ct.yaml")
	image := regexp.MustCompile(`(?m)^make image .*\bIMAGE=(\S+)`).FindStringSubmatch(all)
	require.NotNil(t, image, "the chart installs the image of this commit")
	require.Contains(t, all, "kind load docker-image "+image[1]+":local --name fsk-chart")
	require.Contains(t, all, "ct install --config ct.yaml --charts chart/falcosidekick")
	for _, set := range []string{"--set=image.repository=" + image[1], "--set=image.tag=local", "--set=image.pullPolicy=Never"} {
		require.Contains(t, all, set)
	}
	kind := job.Steps[stepIndex(t, job, "helm/kind-action")]
	require.Equal(t, "fsk-chart", kind.With["cluster_name"])
	policy := readWorkflow(t, "e2e.yml").Jobs["policyreport"]
	policyKind := policy.Steps[stepIndex(t, policy, "helm/kind-action")]
	require.Equal(t, policyKind.With["version"], kind.With["version"], "one kind version")
	require.Less(t, stepIndex(t, job, "helm/kind-action"), len(job.Steps)-1)
	require.Contains(t, job.Steps[0].With, "fetch-depth", "ct compares with the target branch")
	require.Equal(t, "0", job.Steps[0].With["fetch-depth"])
}
