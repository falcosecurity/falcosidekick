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

package shared_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// Startup refuses ui.event_source on the EventSource flag alone, so the flag must match what the driver implements.
func TestEventSourceFlagMatchesReadableStore(t *testing.T) {
	built := map[string]output.Driver{}
	inmemory, err := outputTypes["inmemory"].New(map[string]any{}, output.Deps{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = inmemory.Close() })
	built["inmemory"] = inmemory
	for _, c := range silentCases(t) {
		if c.typ != "" {
			continue
		}
		built[c.name] = c.build(t)
	}

	for name, typ := range outputTypes {
		driver, ok := built[name]
		require.True(t, ok, "output %s was not built", name)
		_, readable := driver.(output.ReadableStore)
		assert.Equal(t, readable, typ.EventSource, "%s: EventSource must be set exactly when the driver implements ReadableStore", name)
	}
	assert.True(t, outputTypes["inmemory"].EventSource, "inmemory is the default ui.event_source")
}
