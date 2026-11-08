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

package metrics

import (
	"context"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// NoopCollector implements core.MetricsCollector with no-op methods.
type NoopCollector struct{}

// RecordInput is a no-op.
func (NoopCollector) RecordInput(_ context.Context, _, _ string) {}

// RecordOutput is a no-op.
func (NoopCollector) RecordOutput(_ context.Context, _, _ string, _ time.Duration) {}

// RecordDrop is a no-op.
func (NoopCollector) RecordDrop(_ context.Context, _ string) {}

// RecordError is a no-op.
func (NoopCollector) RecordError(_ context.Context, _ string, _ error) {}

// RecordEvent is a no-op.
func (NoopCollector) RecordEvent(_ context.Context, _ string, _ event.Priority, _ string) {}
