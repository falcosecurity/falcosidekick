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

package gcppubsub

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"

	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/shared"
)

func TestClientCapsTheReconnectBackoff(t *testing.T) {
	want := option.WithGRPCDialOption(shared.GRPCReconnect)
	for _, tc := range []struct {
		raw  map[string]any
		name string
	}{
		{name: "google cloud", raw: map[string]any{"project_id": testProject, "topic": testTopic}},
		{name: "emulator", raw: map[string]any{"project_id": testProject, "topic": testTopic, "emulator_host": "127.0.0.1:8085"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := createOutput(tc.raw, output.Deps{})
			require.NoError(t, err)
			assert.Contains(t, d.(*driver).clientOptions(), want)
		})
	}
}
