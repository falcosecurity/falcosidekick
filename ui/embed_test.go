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

//go:build builtinui

package ui

import (
	"io/fs"
	"testing"
)

func TestEmbeddedDistIsNonNil(t *testing.T) {
	if Dist == nil {
		t.Fatal("Dist must be non-nil in the builtinui build")
	}
}

func TestEmbeddedEnabledIsTrue(t *testing.T) {
	if !Enabled {
		t.Fatal("Enabled must be true in the builtinui build")
	}
}

func TestEmbeddedIndexHTMLExists(t *testing.T) {
	info, err := fs.Stat(Dist, "index.html")
	if err != nil {
		t.Fatalf("dist/index.html not found via embedded FS: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("dist/index.html must be a file, got a directory")
	}
	if info.Size() == 0 {
		t.Fatal("dist/index.html must not be empty")
	}
}
