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

// RuntimeConfigSchemaFields returns schema fields for the per-output runtime: section of an output
// that delivers events one at a time.
func RuntimeConfigSchemaFields() []output.SchemaField {
	return []output.SchemaField{
		{
			Name: "runtime.minimum_priority", Type: "enum", Label: "Minimum Priority",
			Values:      []string{"debug", "informational", "notice", "warning", "error", "critical", "alert", "emergency"},
			Description: "Events below this priority are not sent to this output. Empty sends every priority.",
		},
		{
			Name: "runtime.queue_size", Type: "int", Default: 1000, Label: "Queue Size",
			Description: "Events this output holds while they wait for delivery. When the queue is full, new events for this output are dropped and counted as dropped.",
		},
		{
			Name: "runtime.workers", Type: "int", Default: 2, Label: "Worker Count",
			Description: "Deliveries this output runs at the same time.",
		},
		{
			Name: "runtime.retry.max_attempts", Type: "int", Default: 3, Label: "Max Retry Attempts",
			Description: "Delivery attempts per event, the first one included. A permanent error, such as rejected credentials, is not retried.",
		},
		{
			Name: "runtime.retry.initial_interval", Type: "string", Default: "1s", Label: "Retry Initial Interval",
			Description: "Wait before the second attempt, as a duration such as `500ms` or `2s`.",
		},
		{
			Name: "runtime.retry.max_interval", Type: "string", Default: "30s", Label: "Retry Max Interval",
			Description: "Longest wait between two attempts, as a duration.",
		},
		{
			Name: "runtime.retry.multiplier", Type: "float", Default: 2.0, Label: "Retry Backoff Multiplier",
			Description: "Factor applied to the wait after each failed attempt, up to the longest wait.",
		},
		{
			Name: "runtime.circuit_breaker.failure_threshold", Type: "int", Default: 5, Label: "Circuit Breaker Failure Threshold",
			Description: "Consecutive failed deliveries that open the circuit. While it is open the output sends nothing and new events wait in the queue.",
		},
		{
			Name: "runtime.circuit_breaker.success_threshold", Type: "int", Default: 2, Label: "Circuit Breaker Success Threshold",
			Description: "Successful deliveries in a row that close the circuit again after the reset timeout.",
		},
		{
			Name: "runtime.circuit_breaker.reset_timeout", Type: "string", Default: "30s", Label: "Circuit Breaker Reset Timeout",
			Description: "Time the circuit stays open before a trial delivery, as a duration.",
		},
		{
			Name: "runtime.health_check", Type: "bool", Default: true, Label: "Probe the destination before starting",
			Description: "Checks the destination at startup, on reload and on API changes, for up to 5 seconds. " +
				"Rejected credentials or a wrong address stop startup or refuse the change.",
		},
	}
}

// BatchRuntimeConfigSchemaFields returns the runtime: fields of an output that implements
// output.BatchSender, which honors runtime.batching.
func BatchRuntimeConfigSchemaFields() []output.SchemaField {
	return append(RuntimeConfigSchemaFields(),
		output.SchemaField{
			Name: "runtime.batching.enabled", Type: "bool", Default: false, Label: "Enable Batching",
			Description: "Sends events in groups, one request per group.",
		},
		output.SchemaField{
			Name: "runtime.batching.batch_size", Type: "int", Default: 500, Label: "Batch Size",
			Description: "Most events in one group.",
		},
		output.SchemaField{
			Name: "runtime.batching.flush_interval", Type: "string", Default: "1s", Label: "Batch Flush Interval",
			Description: "Longest time an incomplete group waits before it is sent, as a duration.",
		},
	)
}
