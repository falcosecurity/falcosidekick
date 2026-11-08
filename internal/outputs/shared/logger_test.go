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

package shared

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveLoggerNilFallsBackToDefault(t *testing.T) {
	logger := ResolveLogger(nil, "test")
	require.NotNil(t, logger)
}

func TestResolveLoggerPreservesProvided(t *testing.T) {
	custom := slog.Default().With("custom", true)
	logger := ResolveLogger(custom, "test")
	assert.NotNil(t, logger)
}

func TestResolveLoggerAddsOutputField(t *testing.T) {
	logger := ResolveLogger(nil, "myoutput")
	assert.NotNil(t, logger)
}
