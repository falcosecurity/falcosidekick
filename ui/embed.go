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
	"embed"
	"io/fs"
)

//go:embed dist/*
var assets embed.FS

// Dist is the embedded UI asset filesystem rooted at the dist/ directory.
var Dist fs.FS = mustSub(assets, "dist")

// Enabled reports whether the binary was built with an embedded UI.
const Enabled = true

func mustSub(embedded embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(embedded, dir)
	if err != nil {
		panic("ui: fs.Sub(" + dir + "): " + err.Error())
	}
	return sub
}
