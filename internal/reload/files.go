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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// fileFieldsDigest digests the contents of the files the File fields of cfg name, or returns ""
// when they name none. Paths inside map entries are read at every request and <name>_file secrets
// are resolved into cfg, so both are left out. Errors name the location, not the path or the OS error.
func fileFieldsDigest(name string, cfg map[string]any, fields []output.SchemaField) (string, error) {
	var fileFields []output.SchemaField
	for i := range fields {
		if fields[i].File {
			fileFields = append(fileFields, fields[i])
		}
	}
	paths := make(map[string]string)
	if err := output.CollectFilePaths(cfg, fileFields, paths); err != nil {
		return "", fmt.Errorf("output %q: %w", name, err)
	}
	if len(paths) == 0 {
		return "", nil
	}
	var sums []byte
	for _, location := range slices.Sorted(maps.Keys(paths)) {
		data, err := utils.ReadRegularFile(paths[location])
		if err != nil {
			return "", fmt.Errorf("output %q: %s: %s", name, location, utils.FileProblem(err))
		}
		sum := sha256.Sum256(data)
		sums = append(sums, location...)
		sums = append(sums, 0)
		sums = append(sums, sum[:]...)
	}
	digest := sha256.Sum256(sums)
	return hex.EncodeToString(digest[:]), nil
}

// SecretPaths lists where the secret files of running outputs live: the api.secret_dirs roots, the
// directories directly below them, such as Kubernetes Secret mounts, and the files the running file
// outputs reference. Entries named ..* are kubelet internals; their swap is seen in the parent directory.
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
