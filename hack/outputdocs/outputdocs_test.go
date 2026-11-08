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
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v4"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/config"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
)

var root = filepath.Join("..", "..")

func readRepo(path string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// The docs follow the schema: a change to a field without `make docs` fails here.
func TestDocsAreUpToDate(t *testing.T) {
	files, err := Generate(all.Types(), readRepo)
	require.NoError(t, err)
	want := make([]string, 0, len(files))
	for _, f := range files {
		current, ok := readRepo(f.Path)
		require.True(t, ok, "%s is missing: run make docs", f.Path)
		assert.Equal(t, f.Content, current, "%s is out of date: run make docs", f.Path)
		want = append(want, filepath.Base(f.Path))
	}
	entries, err := os.ReadDir(filepath.Join(root, Dir))
	require.NoError(t, err)
	for _, e := range entries {
		assert.Contains(t, want, e.Name(), "%s/%s documents no output type", Dir, e.Name())
	}
}

// Every example in the docs is a working output file: it loads, its secrets come from files, it
// builds, and it says no more about batching than the driver does.
func TestEveryExampleBuilds(t *testing.T) {
	cat, err := catalog.New(all.Types())
	require.NoError(t, err)
	for _, typ := range all.Types() {
		t.Run(typ.Name, func(t *testing.T) {
			doc, ok := readRepo(Dir + "/" + typ.Name + ".md")
			require.True(t, ok)
			example, err := Example(doc)
			require.NoError(t, err)

			var file struct {
				Outputs map[string]map[string]any `yaml:"outputs"`
			}
			require.NoError(t, yaml.Unmarshal([]byte(example), &file))
			require.Equal(t, []string{typ.Name}, slices.Collect(mapKeys(file.Outputs)), "the example configures this output only")
			dir := t.TempDir()
			referenceFiles(t, dir, file.Outputs[typ.Name])
			rewritten, err := yaml.Marshal(file)
			require.NoError(t, err)
			path := filepath.Join(dir, "outputs.yaml")
			require.NoError(t, os.WriteFile(path, rewritten, 0o600))

			loaded, err := config.LoadOutputs([]string{path})
			require.NoError(t, err)
			require.NoError(t, config.CheckNoInlineSecrets(loaded.Outputs, cat), "examples keep secrets in files")
			resolved, err := config.ResolvedOutputs(loaded.Outputs, cat)
			require.NoError(t, err)
			driver, err := cat.Create(typ.Name, resolved[typ.Name], output.Deps{Logger: slog.New(slog.DiscardHandler)})
			require.NoError(t, err)
			_, batches := driver.(output.BatchSender)
			assert.Equal(t, batches, HasBatching(&typ), "the batching settings appear exactly when the driver sends batches")
			require.NoError(t, driver.Close())
		})
	}
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// referenceFiles replaces the paths an example names with files in dir holding a value that works
// for that setting, so the example builds as written.
func referenceFiles(t *testing.T, dir string, cfg map[string]any) {
	t.Helper()
	write := func(key, original string) string {
		path := filepath.Join(dir, strings.NewReplacer("/", "_", ".", "_").Replace(strings.TrimPrefix(original, "/")))
		require.NoError(t, os.WriteFile(path, []byte(fileContent(key)), 0o600))
		return path
	}
	for key, value := range cfg {
		switch v := value.(type) {
		case map[string]any:
			referenceFiles(t, dir, v)
		case string:
			if strings.HasSuffix(key, "_file") || key == kubeconfigKey {
				cfg[key] = write(key, v)
			}
		case []any:
			if key == "files" {
				for i, item := range v {
					v[i] = write(key, item.(string))
				}
			}
		}
	}
}

// kubeconfigKey is the policyreport setting that names a file without the _file suffix.
const kubeconfigKey = "kubeconfig"

func fileContent(key string) string {
	switch key {
	case kubeconfigKey:
		return `apiVersion: v1
kind: Config
clusters: [{name: example, cluster: {server: "https://127.0.0.1:6443"}}]
users: [{name: example, user: {token: example}}]
contexts: [{name: example, context: {cluster: example, user: example}}]
current-context: example
`
	case "secret_endpoint_file":
		return "/example/path"
	case "credentials_file":
		return `{"type": "authorized_user", "client_id": "example", "client_secret": "example", "refresh_token": "example"}`
	case "ca_file", "cert_file", "key_file":
		panic("examples do not reference TLS files: a placeholder is not a certificate")
	default:
		return "example-secret"
	}
}

var (
	commentedOutput  = regexp.MustCompile(`^ {2}# [a-z0-9]+:\s*$`)
	commentedSetting = regexp.MustCompile(`^ {2}# ( +)([a-z0-9_.-]+:|- )`)
)

// config_example_outputs.yaml shows outputs as commented blocks; every setting it names must exist
// in that output's schema, so the example cannot drift from the code.
func TestExampleOutputsFileNamesKnownSettings(t *testing.T) {
	text, ok := readRepo("config_example_outputs.yaml")
	require.True(t, ok)
	outputs, err := exampleOutputs(text)
	require.NoError(t, err)
	types := make(map[string]output.Type)
	for _, typ := range all.Types() {
		types[typ.Name] = typ
	}
	for name := range types {
		assert.Contains(t, outputs, name, "config_example_outputs.yaml shows every output")
	}
	assert.Empty(t, unknownSettings(outputs, types))
}

func TestUnknownSettingsAreFound(t *testing.T) {
	text := "core: x\noutputs:\n\n  # ===\n  # Slack\n  # ===\n\n  # slack:\n" +
		"  #   footer: x\n  #   chanel: typo\n  #   # icon_url: commented twice\n" +
		"  #   secret_endpoint_file: /p\n  #   runtime:\n  #     batching:\n  #       enabled: true\n" +
		"  #   headers:\n  #     X-Any:\n  #       values: [a]\n" +
		"\n  # ===\n  # Shared\n  # ===\n  #   region: eu-west-1\n"
	outputs, err := exampleOutputs(text)
	require.NoError(t, err)
	types := map[string]output.Type{}
	for _, typ := range all.Types() {
		if typ.Name == "slack" {
			types["slack"] = typ
		}
	}
	assert.ElementsMatch(t, []string{"slack: chanel", "slack: runtime.batching.enabled"}, unknownSettings(outputs, types))
}

// exampleOutputs reads the commented output blocks of config_example_outputs.yaml. A block starts
// at "  # <output>:" and ends at a "# ===" separator; settings outside a block illustrate fields
// several outputs share, and lines commented twice are left out.
func exampleOutputs(text string) (map[string]map[string]any, error) {
	_, outputsPart, ok := strings.Cut(text, "\noutputs:\n")
	if !ok {
		return nil, errors.New("no outputs: section")
	}
	uncommented := []string{"outputs:"}
	inBlock := false
	for line := range strings.SplitSeq(outputsPart, "\n") {
		switch {
		case commentedOutput.MatchString(line):
			inBlock = true
			uncommented = append(uncommented, "  "+line[len("  # "):])
		case strings.HasPrefix(line, "  # ==="):
			inBlock = false
		case inBlock && commentedSetting.MatchString(line):
			uncommented = append(uncommented, "  "+line[len("  # "):])
		}
	}
	var file struct {
		Outputs map[string]map[string]any `yaml:"outputs"`
	}
	if err := yaml.Unmarshal([]byte(strings.Join(uncommented, "\n")), &file); err != nil {
		return nil, err
	}
	return file.Outputs, nil
}

func unknownSettings(outputs map[string]map[string]any, types map[string]output.Type) []string {
	var unknown []string
	for name, cfg := range outputs {
		typ, ok := types[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		for _, key := range settingKeys("", cfg, typ.Schema.Fields) {
			if !knownSetting(key, typ.Schema.Fields) {
				unknown = append(unknown, name+": "+key)
			}
		}
	}
	return unknown
}

// settingKeys lists the dotted keys of cfg, stopping at map fields, whose keys are names.
func settingKeys(prefix string, cfg map[string]any, fields []output.SchemaField) []string {
	var keys []string
	for key, value := range cfg {
		path := prefix + key
		nested, isMap := value.(map[string]any)
		i := slices.IndexFunc(fields, func(f output.SchemaField) bool { return f.Name == path })
		if isMap && (i < 0 || !fields[i].IsMap()) {
			keys = append(keys, settingKeys(path+".", nested, fields)...)
			continue
		}
		keys = append(keys, path)
	}
	return keys
}

func knownSetting(key string, fields []output.SchemaField) bool {
	return slices.ContainsFunc(fields, func(f output.SchemaField) bool {
		return f.Name == key || (f.HasFileVariant() && f.Name+"_file" == key)
	})
}

func TestReplaceBlockKeepsTheTextAround(t *testing.T) {
	doc := "# Title\n\nhand text\n\n" + emptyBlock("settings") + "\n\nmore hand text\n"
	out, err := replaceBlock(doc, "settings", "generated")
	require.NoError(t, err)
	block := beginMarker("settings") + "\n" + generatedNote + "\n\ngenerated\n\n" + endMarker("settings")
	assert.Equal(t, "# Title\n\nhand text\n\n"+block+"\n\nmore hand text\n", out)
	again, err := replaceBlock(out, "settings", "generated")
	require.NoError(t, err)
	assert.Equal(t, out, again, "replacing is idempotent")
}

func TestReplaceBlockRefusesBrokenMarkers(t *testing.T) {
	for name, doc := range map[string]string{
		"missing":   "# Title\n",
		"twice":     emptyBlock("settings") + "\n" + emptyBlock("settings"),
		"reversed":  endMarker("settings") + "\n" + beginMarker("settings"),
		"other id":  emptyBlock("index"),
		"no ending": beginMarker("settings"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := replaceBlock(doc, "settings", "x")
			assert.Error(t, err)
		})
	}
}

func TestExample(t *testing.T) {
	yamlText, err := Example("intro\n" + exampleMarker + "\n```yaml\noutputs:\n  webhook: {}\n```\n")
	require.NoError(t, err)
	assert.Equal(t, "outputs:\n  webhook: {}\n", yamlText)
	_, err = Example("no marker")
	assert.Error(t, err)
	_, err = Example(exampleMarker + "\nno block")
	assert.Error(t, err)
}

func TestAnchorMatchesGitHub(t *testing.T) {
	assert.Equal(t, "http-authentication-and-headers", anchor("HTTP authentication and headers"))
	assert.Equal(t, "aws-credentials", anchor("AWS credentials"))
}
