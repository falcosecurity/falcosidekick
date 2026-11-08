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

// Package all provides the explicit list of all available output types.
// Adding a new output: import the package and add its Type to the slice.
package all

import (
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/outputs/alertmanager"
	"github.com/falcosecurity/falcosidekick/internal/outputs/elasticsearch"
	"github.com/falcosecurity/falcosidekick/internal/outputs/inmemory"
	"github.com/falcosecurity/falcosidekick/internal/outputs/kafka"
	"github.com/falcosecurity/falcosidekick/internal/outputs/loki"
	"github.com/falcosecurity/falcosidekick/internal/outputs/slack"
	"github.com/falcosecurity/falcosidekick/internal/outputs/webhook"
)

// Types returns all registered output types.
func Types() []output.Type {
	return []output.Type{
		alertmanager.OutputType,
		elasticsearch.OutputType,
		kafka.OutputType,
		loki.OutputType,
		inmemory.OutputType,
		slack.OutputType,
		webhook.OutputType,
	}
}
