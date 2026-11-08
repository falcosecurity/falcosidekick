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
	"cmp"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
	sharedaws "github.com/falcosecurity/falcosidekick/internal/outputs/shared/aws"
)

// Dir holds the documents, relative to the repository root.
const Dir = "docs/outputs"

// File is a document and its content.
type File struct {
	Path    string
	Content string
}

// group is a set of settings several outputs share, documented once in common.md.
type group struct {
	id     string
	title  string
	fields []output.SchemaField
}

func (g group) link() string { return "[" + g.title + "](common.md#" + anchor(g.title) + ")" }

func sharedGroups() []group {
	tls := shared.TLSClientSchemaFields()
	query := slices.DeleteFunc(shared.HTTPTargetSchemaFields(&shared.HTTPTargetOptions{}), func(f output.SchemaField) bool {
		return f.Name != "query_params"
	})
	return []group{
		{id: "query-params", title: "Query parameters", fields: query},
		{id: "http-auth", title: "HTTP authentication and headers", fields: without(shared.HTTPConfigSchemaFields(), tls)},
		{id: "aws", title: "AWS credentials", fields: without(sharedaws.SchemaFields(), tls)},
		{id: "tls", title: "TLS", fields: tls},
		{id: "delivery", title: "Delivery", fields: shared.RuntimeConfigSchemaFields()},
		{id: "batching", title: "Batching", fields: batchingFields()},
	}
}

// batchingFields are the runtime fields only outputs that deliver in groups have.
func batchingFields() []output.SchemaField {
	return without(shared.BatchRuntimeConfigSchemaFields(), shared.RuntimeConfigSchemaFields())
}

// Generate returns every document for types. read returns the current content of a path, or false
// when the document does not exist yet; a new document starts from a skeleton.
func Generate(types []output.Type, read func(path string) (string, bool)) ([]File, error) {
	sorted := slices.SortedFunc(slices.Values(types), func(a, b output.Type) int { return cmp.Compare(a.Name, b.Name) })
	groups := sharedGroups()
	files := make([]File, 0, len(sorted)+2)
	titles := make(map[string]string, len(sorted))
	for i := range sorted {
		t := &sorted[i]
		path := Dir + "/" + t.Name + ".md"
		doc, ok := read(path)
		if !ok {
			doc = pageSkeleton(t)
		}
		doc, err := replaceBlock(doc, "settings", settings(t, groups))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		titles[t.Name] = heading(doc)
		if titles[t.Name] == "" {
			return nil, fmt.Errorf("%s: needs a level-one heading", path)
		}
		files = append(files, File{Path: path, Content: doc})
	}

	common, ok := read(Dir + "/common.md")
	if !ok {
		common = commonSkeleton(groups)
	}
	for _, g := range groups {
		var err error
		if common, err = replaceBlock(common, g.id, table(g.fields)); err != nil {
			return nil, fmt.Errorf("%s/common.md: %w", Dir, err)
		}
	}
	files = append(files, File{Path: Dir + "/common.md", Content: common})

	index, ok := read(Dir + "/README.md")
	if !ok {
		index = indexSkeleton()
	}
	index, err := replaceBlock(index, "index", indexTable(sorted, titles))
	if err != nil {
		return nil, fmt.Errorf("%s/README.md: %w", Dir, err)
	}
	return append(files, File{Path: Dir + "/README.md", Content: index}), nil
}

// HasBatching reports whether t offers the batching settings.
func HasBatching(t *output.Type) bool { return covers(t.Schema.Fields, batchingFields()) }

func settings(t *output.Type, groups []group) string {
	var own []output.SchemaField
	var links []string
	covered := make(map[string]bool)
	for _, g := range groups {
		if covers(t.Schema.Fields, g.fields) {
			links = append(links, g.link())
			for i := range g.fields {
				covered[g.fields[i].Name] = true
			}
		}
	}
	for i := range t.Schema.Fields {
		if !covered[t.Schema.Fields[i].Name] {
			own = append(own, t.Schema.Fields[i])
		}
	}

	text := "## Settings\n\n" +
		fmt.Sprintf("Key in the output file: `%s`. Category: %s. ", t.Name, t.Category.Title()) +
		fmt.Sprintf("UI event source: %s. Batching: %s.\n\n", yesNo(t.EventSource), yesNo(HasBatching(t)))
	if len(own) > 0 {
		text += table(own) + "\n\n"
	}
	if len(links) > 0 {
		text += fmt.Sprintf("Also takes the shared settings in %s.\n", strings.Join(links, ", "))
	}
	return text
}

// covers reports whether fields holds every field of set exactly as the shared builder defines it.
func covers(fields, set []output.SchemaField) bool {
	if len(set) == 0 {
		return false
	}
	for j := range set {
		want := &set[j]
		i := slices.IndexFunc(fields, func(f output.SchemaField) bool { return f.Name == want.Name })
		if i < 0 || !reflect.DeepEqual(&fields[i], want) {
			return false
		}
	}
	return true
}

func without(fields, drop []output.SchemaField) []output.SchemaField {
	return slices.DeleteFunc(slices.Clone(fields), func(f output.SchemaField) bool {
		return slices.ContainsFunc(drop, func(d output.SchemaField) bool { return d.Name == f.Name })
	})
}

func table(fields []output.SchemaField) string {
	lines := []string{"| Setting | Type | Default | Description |", "| --- | --- | --- | --- |"}
	var rows func(prefix string, fields []output.SchemaField)
	rows = func(prefix string, fields []output.SchemaField) {
		for i := range fields {
			f := &fields[i]
			name := prefix + f.Name
			lines = append(lines, fmt.Sprintf("| `%s` | %s | %s | %s |", name, typeText(f), defaultText(f.Default), cell(description(name, f))))
			if len(f.EntryFields) > 0 {
				rows(name+".<name>.", f.EntryFields)
			}
		}
	}
	rows("", fields)
	return strings.Join(lines, "\n")
}

func typeText(f *output.SchemaField) string {
	var text string
	switch f.Type {
	case "int":
		text = "integer"
	case "float":
		text = "number"
	case "bool":
		text = "boolean"
	case "string[]":
		text = "list of strings"
	case "map":
		text = "map by name"
	case "enum":
		values := make([]string, len(f.Values))
		for i, v := range f.Values {
			values[i] = "`" + v + "`"
		}
		text = "one of " + strings.Join(values, ", ")
	default:
		text = f.Type
	}
	if f.File {
		text += ", file path"
	}
	if f.Secret {
		text += ", secret"
	}
	if f.Required {
		text += ", **required**"
	}
	return text
}

func description(name string, f *output.SchemaField) string {
	d := f.Description
	if f.Suggested != nil {
		d += " Suggested: `" + fmt.Sprint(f.Suggested) + "`."
	}
	if f.HasFileVariant() {
		d += " Also accepted as `" + name + "_file`, the path of a file holding the value."
	}
	return d
}

func defaultText(v any) string {
	if v == nil || v == "" {
		return "-"
	}
	return "`" + fmt.Sprint(v) + "`"
}

func cell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func indexTable(types []output.Type, titles map[string]string) string {
	lines := make([]string, 0, 2+len(types))
	lines = append(lines, "| Output | Key | Category | UI event source | Batching |", "| --- | --- | --- | --- | --- |")
	for i := range types {
		t := &types[i]
		lines = append(lines, fmt.Sprintf("| [%s](%s.md) | `%s` | %s | %s | %s |",
			titles[t.Name], t.Name, t.Name, t.Category.Title(), yesNo(t.EventSource), yesNo(HasBatching(t))))
	}
	return strings.Join(lines, "\n")
}

// anchor is the fragment GitHub derives from a heading.
func anchor(title string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		case r == ' ':
			return '-'
		}
		return -1
	}, strings.ToLower(title))
}

func pageSkeleton(t *output.Type) string {
	return "# " + t.Name + "\n\nWhat the output does, how it delivers and its limits.\n\n## Example\n\n" +
		exampleMarker + "\n```yaml\noutputs:\n  " + t.Name + ": {}\n```\n\n" + emptyBlock("settings") + "\n"
}

func commonSkeleton(groups []group) string {
	parts := make([]string, 0, 1+len(groups))
	parts = append(parts, "# Common settings\n")
	for _, g := range groups {
		parts = append(parts, fmt.Sprintf("\n## %s\n\n%s\n", g.title, emptyBlock(g.id)))
	}
	return strings.Join(parts, "")
}

func indexSkeleton() string {
	return "# Outputs\n\n" + emptyBlock("index") + "\n"
}
