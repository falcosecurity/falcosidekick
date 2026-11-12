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
	"hash"
	"os"
)

// snapshot keys the input one file reconcile read; the same input gives the same key.
type snapshot struct {
	h hash.Hash
}

func newSnapshot() *snapshot {
	return &snapshot{h: sha256.New()}
}

// addFiles adds the bytes of each output file, read before they are parsed.
func (s *snapshot) addFiles(paths []string) {
	for _, path := range paths {
		data, err := os.ReadFile(path) //nolint:gosec // user-provided config file path
		if err != nil {
			s.add(path, "unreadable")
			continue
		}
		s.add(path, sha256.Sum256(data))
	}
}

// add writes each value; fmt prints maps sorted by key, so equal configs write the same bytes.
func (s *snapshot) add(values ...any) {
	for _, v := range values {
		_, _ = fmt.Fprintf(s.h, "%#v\x00", v)
	}
}

// key returns the key of what was added so far; later adds extend it.
func (s *snapshot) key() string {
	return hex.EncodeToString(s.h.Sum(nil))
}
