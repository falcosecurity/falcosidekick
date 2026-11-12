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

	"github.com/falcosecurity/falcosidekick/internal/domain/event"
	"github.com/falcosecurity/falcosidekick/internal/domain/output"
	"github.com/falcosecurity/falcosidekick/internal/utils"
)

// MergeRuntimeConfig overlays the positive per-output runtime fields on the defaults and validates the
// result; a zero field is an omitted one. Schema.NormalizeConfig ranges the raw values before decoding.
func MergeRuntimeConfig(defaults output.RuntimeConfig, name string, perOutput output.RuntimeConfig) (output.RuntimeConfig, error) {
	resolved := defaults.DeepCopy()

	if perOutput.QueueSize > 0 {
		resolved.QueueSize = perOutput.QueueSize
	}
	if perOutput.Workers > 0 {
		resolved.Workers = perOutput.Workers
	}
	if perOutput.MinPriority != "" {
		resolved.MinPriority = perOutput.MinPriority
	}
	// The filter compares canonical priorities; the configuration accepts any case.
	if resolved.MinPriority != "" {
		priority, err := event.ParsePriority(string(resolved.MinPriority))
		if err != nil {
			return resolved, fmt.Errorf("output %q: minimum_priority: must be a Falco priority", name)
		}
		resolved.MinPriority = priority
	}
	if perOutput.Retry != nil {
		merged := *resolved.Retry
		if perOutput.Retry.MaxAttempts > 0 {
			merged.MaxAttempts = perOutput.Retry.MaxAttempts
		}
		if perOutput.Retry.InitialInterval > 0 {
			merged.InitialInterval = perOutput.Retry.InitialInterval
		}
		if perOutput.Retry.MaxInterval > 0 {
			merged.MaxInterval = perOutput.Retry.MaxInterval
		}
		if perOutput.Retry.Multiplier > 0 {
			merged.Multiplier = perOutput.Retry.Multiplier
		}
		resolved.Retry = &merged
	}
	if perOutput.CircuitBreaker != nil {
		merged := *resolved.CircuitBreaker
		if perOutput.CircuitBreaker.FailureThreshold > 0 {
			merged.FailureThreshold = perOutput.CircuitBreaker.FailureThreshold
		}
		if perOutput.CircuitBreaker.SuccessThreshold > 0 {
			merged.SuccessThreshold = perOutput.CircuitBreaker.SuccessThreshold
		}
		if perOutput.CircuitBreaker.ResetTimeout > 0 {
			merged.ResetTimeout = perOutput.CircuitBreaker.ResetTimeout
		}
		resolved.CircuitBreaker = &merged
	}
	if perOutput.Batching != nil {
		var merged output.BatchingConfig
		if resolved.Batching != nil {
			merged = *resolved.Batching
		}
		// An omitted enabled inherits the default; an explicit false disables.
		if perOutput.Batching.Enabled != nil {
			merged.Enabled = new(*perOutput.Batching.Enabled)
		}
		if perOutput.Batching.BatchSize > 0 {
			merged.BatchSize = perOutput.Batching.BatchSize
		}
		if perOutput.Batching.FlushInterval > 0 {
			merged.FlushInterval = perOutput.Batching.FlushInterval
		}
		resolved.Batching = &merged
	}
	if perOutput.HealthCheck != nil {
		enabled := *perOutput.HealthCheck
		resolved.HealthCheck = &enabled
	}

	if errs := resolved.Validate(); len(errs) > 0 {
		var prefixed utils.ValidationErrors
		prefixed.Merge("runtime", errs)
		return resolved, fmt.Errorf("output %q: %w", name, prefixed)
	}

	return resolved, nil
}
