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

// Command outputdocs writes docs/outputs from the output schema: a page per output type, the
// settings several outputs share and an index. Only the blocks between the generated markers
// change; the text around them is written by hand and kept. Run it from the repository root; with
// -check it writes nothing and fails when a document is out of date.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/falcosecurity/falcosidekick/internal/outputs/all"
)

func main() {
	check := flag.Bool("check", false, "fail when a document differs instead of writing it")
	flag.Parse()
	if err := run(*check); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "outputdocs:", err)
		os.Exit(1)
	}
}

func run(check bool) error {
	files, err := Generate(all.Types(), read)
	if err != nil {
		return err
	}
	var stale []string
	for _, f := range files {
		if current, ok := read(f.Path); ok && current == f.Content {
			continue
		}
		if check {
			stale = append(stale, f.Path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(f.Path, []byte(f.Content), 0o644); err != nil { //nolint:gosec // documentation files
			return err
		}
		_, _ = fmt.Println("wrote", f.Path)
	}
	if len(stale) > 0 {
		return fmt.Errorf("out of date, run make docs: %v", stale)
	}
	return nil
}

func read(path string) (string, bool) {
	b, err := os.ReadFile(path) //nolint:gosec // paths come from the generator
	if err != nil {
		return "", false
	}
	return string(b), true
}
