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
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
)

// RuntimeConfigSchemaFields returns schema fields for the per-output runtime: section.
func RuntimeConfigSchemaFields() []output.SchemaField {
	return []output.SchemaField{
		{Name: "runtime.minimum_priority", Type: "enum", Values: []string{
			"debug", "informational", "notice", "warning", "error", "critical", "alert", "emergency",
		}, Label: "Minimum Priority"},
		{Name: "runtime.queue_size", Type: "int", Default: 1000, Label: "Queue Size"},
		{Name: "runtime.workers", Type: "int", Default: 2, Label: "Worker Count"},
		{Name: "runtime.retry.max_attempts", Type: "int", Default: 3, Label: "Max Retry Attempts"},
		{Name: "runtime.retry.initial_interval", Type: "string", Default: "1s", Label: "Retry Initial Interval"},
		{Name: "runtime.retry.max_interval", Type: "string", Default: "30s", Label: "Retry Max Interval"},
		{Name: "runtime.retry.multiplier", Type: "float", Default: 2.0, Label: "Retry Backoff Multiplier"},
		{Name: "runtime.circuit_breaker.failure_threshold", Type: "int", Default: 5, Label: "Circuit Breaker Failure Threshold"},
		{Name: "runtime.circuit_breaker.success_threshold", Type: "int", Default: 2, Label: "Circuit Breaker Success Threshold"},
		{Name: "runtime.circuit_breaker.reset_timeout", Type: "string", Default: "30s", Label: "Circuit Breaker Reset Timeout"},
		{Name: "runtime.batching.enabled", Type: "bool", Default: false, Label: "Enable Batching"},
		{Name: "runtime.batching.batch_size", Type: "int", Default: 500, Label: "Batch Size"},
		{Name: "runtime.batching.flush_interval", Type: "string", Default: "1s", Label: "Batch Flush Interval"},
	}
}
