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

package api

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// One message for every refused path, so the API does not tell which files exist.
var (
	errFilePathsDisabled = errors.New("file paths sent through the API need api.secret_dirs")
	errFileOutsideDirs   = errors.New("must name a regular file of at most 1 MiB inside api.secret_dirs")
)

// checkFilePaths refuses a file path the request adds or changes unless it resolves, after symlinks,
// to a regular file of at most utils.MaxFileSize inside api.secret_dirs. Paths already stored at the
// same place were accepted before, from an output file or an earlier request.
func checkFilePaths(stored, merged map[string]any, fields []output.SchemaField, secretDirs []string) error {
	before := make(map[string]string)
	_ = collectFilePaths(stored, fields, "", before)
	after := make(map[string]string)
	if err := collectFilePaths(merged, fields, "", after); err != nil {
		return err
	}
	locations := make([]string, 0, len(after))
	for location, path := range after {
		if before[location] != path {
			locations = append(locations, location)
		}
	}
	slices.Sort(locations)
	for _, location := range locations {
		if err := allowedFile(after[location], secretDirs); err != nil {
			return fmt.Errorf("%s: %w", location, err)
		}
	}
	return nil
}

// collectFilePaths maps each location of cfg that holds a file path to that path: File fields,
// <name>_file of secret strings, and the same inside map entries. cfg has schema key spelling.
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

func allowedFile(path string, secretDirs []string) error {
	if len(secretDirs) == 0 {
		return errFilePathsDisabled
	}
	if !filepath.IsAbs(path) {
		return errFileOutsideDirs
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return errFileOutsideDirs
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() > utils.MaxFileSize {
		return errFileOutsideDirs
	}
	for _, dir := range secretDirs {
		resolvedDir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(resolvedDir, resolved)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
	}
	return errFileOutsideDirs
}
