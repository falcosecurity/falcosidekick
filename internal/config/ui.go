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

package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/falcosecurity/falcosidekick/internal/catalog"
	"github.com/falcosecurity/falcosidekick/internal/domain/core"
)

// CheckEventSource refuses a ui.event_source naming an output type that cannot serve events to the UI.
// Unknown names are left to startup, which refuses them unless a stored output of that name failed to build.
func CheckEventSource(ui *core.UIConfig, cat *catalog.Catalog) error {
	if !ui.Enabled {
		return nil
	}
	outputType, ok := cat.Get(ui.EventSource)
	if !ok || outputType.EventSource {
		return nil
	}
	var sources []string
	for _, typ := range cat.All() {
		if typ.EventSource {
			sources = append(sources, typ.Name)
		}
	}
	if len(sources) == 0 {
		return fmt.Errorf("ui.event_source: output type %q cannot serve events to the UI", ui.EventSource)
	}
	slices.Sort(sources)
	return fmt.Errorf("ui.event_source: output type %q cannot serve events to the UI; use one of: %s",
		ui.EventSource, strings.Join(sources, ", "))
}
