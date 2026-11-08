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
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// maxListedSecretFiles bounds the files GET /api/v1/secrets returns across every directory.
const maxListedSecretFiles = 1000

// secretDirListing lists one api.secret_dirs entry: its own files and its subdirectories, each a
// mounted Secret whose files are its keys.
type secretDirListing struct {
	Path    string          `json:"path"`
	Keys    []string        `json:"keys"`
	Secrets []secretListing `json:"secrets"`
}

type secretListing struct {
	Name string   `json:"name"`
	Path string   `json:"path"`
	Keys []string `json:"keys"`
}

type secretsResponse struct {
	Dirs      []secretDirListing `json:"dirs"`
	Truncated bool               `json:"truncated"`
}

// handleGetSecrets lists the files an output can name through the API, names only: the same files
// checkFilePaths accepts. Contents are never read.
func (s *Server) handleGetSecrets(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(listSecretDirs(s.secretDirs, maxListedSecretFiles))
}

func listSecretDirs(dirs []string, limit int) secretsResponse {
	res := secretsResponse{Dirs: make([]secretDirListing, 0, len(dirs))}
	budget := limit
	for _, dir := range dirs {
		listing := secretDirListing{Path: dir, Keys: []string{}, Secrets: []secretListing{}}
		root, err := filepath.EvalSymlinks(dir)
		if err != nil {
			res.Dirs = append(res.Dirs, listing)
			continue
		}
		files, subdirs := readSecretDir(dir, root)
		listing.Keys, res.Truncated = takeKeys(files, &budget, res.Truncated)
		for _, name := range subdirs {
			path := filepath.Join(dir, name)
			keys, _ := readSecretDir(path, root)
			if len(keys) == 0 {
				continue
			}
			secret := secretListing{Name: name, Path: path}
			secret.Keys, res.Truncated = takeKeys(keys, &budget, res.Truncated)
			if len(secret.Keys) > 0 {
				listing.Secrets = append(listing.Secrets, secret)
			}
		}
		res.Dirs = append(res.Dirs, listing)
	}
	return res
}

// readSecretDir returns the sorted names of dir's files an output may use and of its subdirectories.
// Hidden entries are skipped, Kubernetes ..data and timestamped directories included. A file counts
// when it resolves to a regular file of at most utils.MaxFileSize inside root.
func readSecretDir(dir, root string) (files, subdirs []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		resolved, err := filepath.EvalSymlinks(filepath.Join(dir, name))
		if err != nil || !within(root, resolved) {
			continue
		}
		info, err := os.Stat(resolved)
		switch {
		case err != nil:
		case info.IsDir():
			subdirs = append(subdirs, name)
		case info.Mode().IsRegular() && info.Size() <= utils.MaxFileSize:
			files = append(files, name)
		}
	}
	slices.Sort(files)
	slices.Sort(subdirs)
	return files, subdirs
}

func takeKeys(keys []string, budget *int, truncated bool) ([]string, bool) {
	if keys == nil {
		return []string{}, truncated
	}
	if len(keys) > *budget {
		keys = keys[:*budget]
		truncated = true
	}
	*budget -= len(keys)
	return keys, truncated
}
