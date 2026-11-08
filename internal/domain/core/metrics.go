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

package core

import (
	"context"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
)

// MetricsCollector defines unified observability operations.
type MetricsCollector interface {
	RecordInput(ctx context.Context, source string, status string)
	RecordOutput(ctx context.Context, output string, status string, duration time.Duration)
	RecordDrop(ctx context.Context, output string)
	RecordError(ctx context.Context, component string, err error)
	RecordEvent(ctx context.Context, rule string, priority event.Priority, source string)
}
