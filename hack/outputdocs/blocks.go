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
	"fmt"
	"strings"
)

const (
	generatedNote = "<!-- Generated from the output schema by `make docs`. Do not edit. -->"
	exampleMarker = "<!-- example -->"
)

func beginMarker(id string) string { return "<!-- BEGIN GENERATED: " + id + " -->" }
func endMarker(id string) string   { return "<!-- END GENERATED: " + id + " -->" }

// emptyBlock is the placeholder a new document gets for a generated block.
func emptyBlock(id string) string { return beginMarker(id) + "\n" + endMarker(id) }

// replaceBlock puts body between the markers of block id and keeps everything outside them.
func replaceBlock(doc, id, body string) (string, error) {
	begin, end := beginMarker(id), endMarker(id)
	if strings.Count(doc, begin) != 1 || strings.Count(doc, end) != 1 {
		return "", fmt.Errorf("needs exactly one %q and one %q", begin, end)
	}
	start := strings.Index(doc, begin)
	stop := strings.Index(doc, end)
	if stop < start {
		return "", fmt.Errorf("%q comes before %q", end, begin)
	}
	block := begin + "\n" + generatedNote + "\n\n" + strings.TrimSpace(body) + "\n\n" + end
	return doc[:start] + block + doc[stop+len(end):], nil
}

// Example returns the YAML of the block that follows the example marker of a document.
func Example(doc string) (string, error) {
	_, after, ok := strings.Cut(doc, exampleMarker)
	if !ok {
		return "", errors.New("no " + exampleMarker + " marker")
	}
	_, after, ok = strings.Cut(after, "```yaml\n")
	if !ok {
		return "", errors.New("no ```yaml block after " + exampleMarker)
	}
	yaml, _, ok := strings.Cut(after, "```")
	if !ok {
		return "", errors.New("the example block is not closed")
	}
	return yaml, nil
}

// heading returns the text of the first level-one heading of a document.
func heading(doc string) string {
	for line := range strings.SplitSeq(doc, "\n") {
		if title, ok := strings.CutPrefix(line, "# "); ok {
			return strings.TrimSpace(title)
		}
	}
	return ""
}
