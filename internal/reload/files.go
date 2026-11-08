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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// CollectFilePaths maps each location of cfg that holds a file path to that path: File fields,
// <name>_file of secret strings, and the same inside map entries. cfg has schema key spelling.
// On a value that is not a path it returns an error; paths keeps what was collected before it.
func CollectFilePaths(cfg map[string]any, fields []output.SchemaField, paths map[string]string) error {
	return collectFilePaths(cfg, fields, "", paths)
}

func collectFilePaths(cfg map[string]any, fields []output.SchemaField, prefix string, paths map[string]string) error {
	for i := range fields {
		field := &fields[i]
		parent, leaf := utils.NavigateMap(cfg, field.Name)
		if parent == nil {
			continue
		}
		location := prefix + field.Name
		switch {
		case field.File:
			if err := addFilePaths(paths, location, parent[leaf]); err != nil {
				return err
			}
		case field.HasFileVariant():
			if err := addFilePaths(paths, location+"_file", parent[leaf+"_file"]); err != nil {
				return err
			}
		case len(field.EntryFields) > 0:
			entries, _ := parent[leaf].(map[string]any)
			for key, entry := range entries {
				if object, ok := entry.(map[string]any); ok {
					entryPrefix := location + "[" + strconv.Quote(key) + "]."
					if err := collectFilePaths(object, field.EntryFields, entryPrefix, paths); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func addFilePaths(paths map[string]string, location string, value any) error {
	switch value := value.(type) {
	case nil:
	case string:
		if value != "" {
			paths[location] = value
		}
	case []any:
		for i, item := range value {
			path, ok := item.(string)
			if !ok {
				return fmt.Errorf("%s[%d]: must be a string", location, i)
			}
			paths[location+"["+strconv.Itoa(i)+"]"] = path
		}
	case []string:
		for i, path := range value {
			paths[location+"["+strconv.Itoa(i)+"]"] = path
		}
	default:
		return fmt.Errorf("%s: must be a file path", location)
	}
	return nil
}

// SecretPaths lists where the secret files of running outputs live: the api.secret_dirs roots, the
// directories directly below them, such as Kubernetes Secret mounts, and the files the running file
// outputs reference. Entries named ..* are kubelet internals and are skipped; their swap is seen in
// the directory that holds them.
type SecretPaths struct {
	referenced func() []string
	roots      []string
}

// NewSecretPaths returns the secret locations for roots and the files referenced returns.
func NewSecretPaths(roots []string, referenced func() []string) *SecretPaths {
	cleaned := make([]string, len(roots))
	for i, root := range roots {
		cleaned[i] = filepath.Clean(root)
	}
	return &SecretPaths{roots: cleaned, referenced: referenced}
}

// Dirs returns the roots, the directories directly below them, and the directory of each referenced
// file, sorted and without duplicates.
func (s *SecretPaths) Dirs() []string {
	dirs := s.mountDirs()
	for _, file := range s.referencedFiles() {
		dirs = append(dirs, filepath.Dir(file))
	}
	slices.Sort(dirs)
	return slices.Compact(dirs)
}

// Files returns the referenced files and the files directly inside the roots and the directories
// below them, sorted and without duplicates.
func (s *SecretPaths) Files() []string {
	files := s.referencedFiles()
	for _, dir := range s.mountDirs() {
		for _, entry := range visibleEntries(dir) {
			if info, err := os.Stat(entry); err == nil && info.Mode().IsRegular() {
				files = append(files, entry)
			}
		}
	}
	slices.Sort(files)
	return slices.Compact(files)
}

func (s *SecretPaths) referencedFiles() []string {
	if s.referenced == nil {
		return nil
	}
	files := s.referenced()
	cleaned := make([]string, 0, len(files))
	for _, file := range files {
		cleaned = append(cleaned, filepath.Clean(file))
	}
	return cleaned
}

// mountDirs returns the roots and the directories directly below them; symlinks are followed.
func (s *SecretPaths) mountDirs() []string {
	dirs := slices.Clone(s.roots)
	for _, root := range s.roots {
		for _, entry := range visibleEntries(root) {
			if info, err := os.Stat(entry); err == nil && info.IsDir() {
				dirs = append(dirs, entry)
			}
		}
	}
	return dirs
}

// visibleEntries returns the paths of the entries of dir not named ..*; an unreadable dir has none.
func visibleEntries(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "..") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths
}
